"""SWC Registry lookup: maps vulnerability names to SWC entries with fuzzy matching."""
from __future__ import annotations

import re
from typing import Dict, List

import pandas as pd


# Aliases for semantic mismatches that normalized string matching won't resolve
_ALIASES: Dict[str, List[str]] = {
    "arithmetic":                                   ["integer overflow and underflow"],
    "bad randomness":                               ["weak sources of randomness from chain attributes"],
    "unsafe delegatecall":                          ["delegatecall to untrusted callee"],
    "direct call to untrusted contract":            ["delegatecall to untrusted callee"],
    "denial of service":                            ["dos with failed call", "dos with block gas limit", "insufficient gas griefing"],
    "time manipulation":                            ["block values as a proxy for time"],
    "contract affected by miners":                  ["block values as a proxy for time"],
    "suicidal contract":                            ["unprotected selfdestruct instruction"],
    "unchecked low level calls":                    ["unchecked call return value"],
    "tx origin for authentication":                 ["authorization through txorigin"],
    "uninitialized local variables":                ["uninitialized storage pointer"],
    "front running":                                ["transaction order dependence"],
    "unused variables":                             ["presence of unused variables"],
    "unlimited compiler versions":                  ["floating pragma"],
    "visibility errors including unrestricted action": ["function default visibility", "state variable default visibility"],
}

_MAX_CODE_CHARS = 600  # chars per code snippet before truncation


def _norm(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", "", s.lower().strip()))


class SWCLookup:
    """Look up SWC registry entries by vulnerability name."""

    def __init__(self, df: pd.DataFrame) -> None:
        self._df = df
        self._index: Dict[str, List[dict]] = {}
        for _, row in df.iterrows():
            key = _norm(str(row["swc_title"]))
            self._index.setdefault(key, []).append(row.to_dict())

    @classmethod
    def from_csv(cls, path: str) -> "SWCLookup":
        return cls(pd.read_csv(path))

    def _find_rows(self, normalized: str) -> List[dict]:
        # 1. Exact match after normalization
        if normalized in self._index:
            return self._index[normalized]

        # 2. Hardcoded aliases for semantic mismatches
        alias_targets = _ALIASES.get(normalized, [])
        rows: List[dict] = []
        for target in alias_targets:
            for key, r in self._index.items():
                if target in key or key in target:
                    rows.extend(r)
        if rows:
            return rows

        # 3. Substring containment (handles minor wording differences)
        for key, r in self._index.items():
            if normalized in key or key in normalized:
                return r

        return []

    def lookup_formatted(self, vulnerability_name: str) -> str:
        """Return a formatted SWC reference block, or '' if no match found."""
        rows = self._find_rows(_norm(vulnerability_name))
        if not rows:
            return ""

        seen_titles: set = set()
        parts: List[str] = []

        for row in rows:
            title = str(row.get("swc_title", ""))
            swc_id = str(row.get("swc_id", ""))
            if title in seen_titles:
                continue
            seen_titles.add(title)

            block = f"[{swc_id}] {title}\n"
            block += f"Remediation: {str(row.get('swc_remediation', '')).strip()}"

            has_fix = str(row.get("has_fix", "")).strip().lower() == "true"
            vuln_code = str(row.get("vulnerable_code", "")).strip()
            fixed_code = str(row.get("fixed_code", "")).strip()

            if has_fix and vuln_code and vuln_code != "nan":
                snip = vuln_code[:_MAX_CODE_CHARS]
                if len(vuln_code) > _MAX_CODE_CHARS:
                    snip += "\n// ... [truncated]"
                block += f"\n\nVulnerable pattern:\n```solidity\n{snip}\n```"

            if has_fix and fixed_code and fixed_code != "nan":
                snip = fixed_code[:_MAX_CODE_CHARS]
                if len(fixed_code) > _MAX_CODE_CHARS:
                    snip += "\n// ... [truncated]"
                block += f"\n\nFixed pattern:\n```solidity\n{snip}\n```"

            parts.append(block)

        return "\n\n---\n\n".join(parts)
