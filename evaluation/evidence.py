"""Evidence admissibility for Detector issues — MEASUREMENT ONLY.

The Detector prompt requires every reported issue to (a) name the target
vulnerability, (b) carry line numbers, and (c) quote copied code as evidence
(pipeline/prompt.py, "Output Rules"). Nothing in the pipeline ever checked any
of the three: the verdict is `len(issues) > 0` (pipeline/nodes.py).

This module computes whether each issue would satisfy those requirements, so
the rate can be measured on a finished run before deciding whether to turn the
check into a decision rule. **It does not affect any verdict.**

Snippet caveat — read before using the numbers
----------------------------------------------
`models.schemas.VulnerabilityIssue` has no field for a code snippet; its fields
are `issue`, `description`, `severity`, `line_numbers`. Quoted code therefore
lands inside the free-text `description`, and criterion (c) has to recover it
heuristically. Adding a structured `code_snippet` field was rejected for this
purpose: the schema is injected verbatim into the Detector prompt via
`PydanticOutputParser.get_format_instructions()`, so adding a field changes the
prompt and therefore the model's behaviour — which would stop this from being
instrumentation.

Consequence: `n_issues_admissible` is a **lower bound**. An issue that cites
real evidence in prose the extractor cannot recognise counts as inadmissible.
The per-criterion counts are reported alongside it so the gap is visible.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence


# ─── Normalisation ────────────────────────────────────────────────────────────

def _norm_ws(s: str) -> str:
    """Collapse every whitespace run to a single space."""
    return re.sub(r"\s+", " ", str(s)).strip()


def _norm_label(s: str) -> str:
    """Lowercase; any run of non-alphanumerics becomes one space.

    Matches evaluation.metrics._norm_label, so `access_control`, `Access
    Control` and `access control` compare equal.
    """
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


# ─── Snippet extraction ───────────────────────────────────────────────────────

# Backticked spans are an explicit citation marker, so they are accepted even
# when they hold a bare identifier (e.g. `authorizedSwapExactTokensForTokens`).
_BACKTICK_RE = re.compile(r"`([^`\n]{4,300})`")

# Double-quoted spans are treated like backticks when they look like code.
_DQUOTE_RE = re.compile(r'"([^"\n]{6,300})"')

# Unmarked prose: only runs that actually look like Solidity are considered,
# so ordinary English words that happen to occur in the contract do not count.
_CODEISH_RE = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$\.\[\]]*\s*"          # an identifier / member chain
    r"(?:\([^()\n]{0,200}\)|\{[^{}\n]{0,200}\}"    # a call or a block
    r"|\s*(?:==|!=|<=|>=|=|\+=|-=)\s*[^;\n]{1,120})"  # or a comparison/assignment
)

_CODE_CHARS = set("(){}[];=.")

_MIN_BACKTICK_LEN = 4
_MIN_PROSE_LEN = 6


def extract_snippets(text: str) -> List[str]:
    """Return candidate code snippets quoted inside *text*, most explicit first.

    Three sources, in descending order of reliability: backticked spans,
    code-looking double-quoted spans, and unmarked runs that match a Solidity
    call/assignment shape.
    """
    if not text:
        return []
    text = str(text)
    out: List[str] = []
    seen: set = set()

    def _add(cand: str, min_len: int, require_code_chars: bool) -> None:
        cand = _norm_ws(cand)
        if len(cand) < min_len:
            return
        if require_code_chars and not (_CODE_CHARS & set(cand)):
            return
        if cand not in seen:
            seen.add(cand)
            out.append(cand)

    for m in _BACKTICK_RE.finditer(text):
        _add(m.group(1), _MIN_BACKTICK_LEN, require_code_chars=False)
    for m in _DQUOTE_RE.finditer(text):
        _add(m.group(1), _MIN_PROSE_LEN, require_code_chars=True)
    for m in _CODEISH_RE.finditer(text):
        _add(m.group(0), _MIN_PROSE_LEN, require_code_chars=True)

    return out


def snippet_found_in_code(text: str, normalised_code: str) -> bool:
    """True if any snippet quoted in *text* occurs literally in the contract.

    *normalised_code* must already be whitespace-normalised (see
    `normalise_code`); snippets are normalised the same way before the test, so
    the comparison ignores indentation and line breaks but nothing else.
    """
    if not normalised_code:
        return False
    return any(s in normalised_code for s in extract_snippets(text))


def normalise_code(code: str) -> str:
    """Whitespace-normalise a contract once, for repeated snippet tests."""
    return _norm_ws(code)


# ─── Per-criterion checks ─────────────────────────────────────────────────────

def has_line_numbers(issue: Dict[str, Any]) -> bool:
    """(a) `line_numbers` is a non-empty list."""
    lines = issue.get("line_numbers")
    return isinstance(lines, (list, tuple)) and len(lines) > 0


def type_matches_target(issue: Dict[str, Any], target: str) -> bool:
    """(b) the issue's type field refers to the target vulnerability.

    Normalised equality, or containment either way — the same tolerance the
    triage node and OWASPLookup already apply to model-written names, so
    `reentrancy` matches `Reentrancy Attack`.
    """
    issue_type = _norm_label(issue.get("issue", ""))
    tgt = _norm_label(target)
    if not issue_type or not tgt:
        return False
    return issue_type == tgt or tgt in issue_type or issue_type in tgt


def cites_code(issue: Dict[str, Any], normalised_code: str) -> bool:
    """(c) the issue quotes code that really occurs in the contract.

    Heuristic — see the module docstring. Both `description` and `issue` are
    searched, since models sometimes put the quote in either.
    """
    for field in ("description", "issue"):
        if snippet_found_in_code(issue.get(field, ""), normalised_code):
            return True
    return False


def _issue_is_admissible(issue: Dict[str, Any], code: str, target: str) -> bool:
    """True when the issue satisfies all three evidence requirements.

    *code* may be raw or pre-normalised; prefer `issue_evidence_counts` when
    checking several issues against the same contract.
    """
    if not isinstance(issue, dict):
        return False
    normalised = normalise_code(code)
    return (
        has_line_numbers(issue)
        and cites_code(issue, normalised)
        and type_matches_target(issue, target)
    )


# ─── Aggregate over a pair's issues ───────────────────────────────────────────

def issue_evidence_counts(
    issues: Sequence[Any],
    code: str,
    target: str,
) -> Dict[str, int]:
    """Count, over one pair's issues, how many meet each evidence criterion.

    Returns `n_issues_admissible` (all three) plus the three per-criterion
    counts, so the strictness of each can be calibrated separately before any
    of it is wired into a decision.
    """
    counts = {
        "n_issues_admissible": 0,
        "n_issues_with_lines": 0,
        "n_issues_with_snippet": 0,
        "n_issues_type_match": 0,
    }
    if not issues:
        return counts

    normalised = normalise_code(code)
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        a = has_line_numbers(issue)
        b = cites_code(issue, normalised)
        c = type_matches_target(issue, target)
        counts["n_issues_with_lines"] += int(a)
        counts["n_issues_with_snippet"] += int(b)
        counts["n_issues_type_match"] += int(c)
        counts["n_issues_admissible"] += int(a and b and c)
    return counts
