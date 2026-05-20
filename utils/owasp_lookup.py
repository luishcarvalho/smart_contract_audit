"""OWASP SCWE lookup: maps vulnerability names to SCWE entries with fuzzy matching."""
from __future__ import annotations

import re
from typing import Dict, List

import pandas as pd


# Aliases for semantic mismatches that normalized string matching won't resolve
_ALIASES: Dict[str, List[str]] = {
    "arithmetic":                                        ["integer overflows and underflows"],
    "bad randomness":                                    ["weak randomness sources"],
    "unsafe delegatecall":                               ["insecure delegatecall usage"],
    "direct call to untrusted contract":                 ["insecure use of external calls"],
    "denial of service":                                 ["dos with block gas limit", "insufficient gas griefing"],
    "time manipulation":                                 ["block values as a proxy for time"],
    "contract affected by miners":                       ["insecure use of block variables"],
    "suicidal contract":                                 ["unprotected selfdestruct instruction"],
    "unchecked low level calls":                         ["unchecked call return value"],
    "tx origin for authentication":                      ["use of txorigin for authorization"],
    "uninitialized local variables":                     ["uninitialized storage pointer"],
    "front running":                                     ["insufficient protection against frontrunning"],
    "unused variables":                                  ["presence of unused variables"],
    "unlimited compiler versions":                       ["floating pragma"],
    "visibility errors including unrestricted action":   ["missing explicit function visibility", "state variable default visibility"],
    "reentrancy":                                        ["reentrancy attacks"],
    "access control":                                    ["insufficient authorization checks"],
    "code with no effects":                              ["dead code"],
    "function default visibility":                        ["missing explicit function visibility"],
    "onchain oracle manipulation":                        ["price oracle manipulation"],
    "unfair slippage protection":                        ["missing slippage protection in automated token swaps"],
    "unexpected ether balance":                          ["incorrect ether balance tracking"],
    "transaction order dependence":                      ["transaction order dependence"],
}

_MAX_CODE_CHARS = 600  # chars per code snippet before truncation


def _norm(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", "", s.lower().strip()))


class OWASPLookup:
    """Look up OWASP SCWE entries by vulnerability name."""

    def __init__(self, df: pd.DataFrame) -> None:
        self._df = df
        self._index: Dict[str, List[dict]] = {}
        for _, row in df.iterrows():
            key = _norm(str(row["name"]))
            self._index.setdefault(key, []).append(row.to_dict())

    @classmethod
    def from_csv(cls, path: str) -> "OWASPLookup":
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

    def lookup_description(self, vulnerability_name: str) -> str:
        """Return the OWASP SCWE description for *vulnerability_name*, or '' if no match."""
        rows = self._find_rows(_norm(vulnerability_name))
        if not rows:
            return ""
        desc = str(rows[0].get("description", "")).strip()
        return desc if desc and desc != "nan" else ""

    def lookup_formatted(self, vulnerability_name: str) -> str:
        """Return a formatted OWASP SCWE reference block, or '' if no match found."""
        rows = self._find_rows(_norm(vulnerability_name))
        if not rows:
            return ""

        seen_names: set = set()
        parts: List[str] = []

        for row in rows:
            name = str(row.get("name", ""))
            scwe_id = str(row.get("id", ""))
            if name in seen_names:
                continue
            seen_names.add(name)

            block = f"[{scwe_id}] {name}\n"
            block += f"Remediation: {str(row.get('remediation', '')).strip()}"

            vuln_code = str(row.get("example_vulnerable", "")).strip()
            fixed_code = str(row.get("example_fixed", "")).strip()

            if vuln_code and vuln_code != "nan":
                snip = vuln_code[:_MAX_CODE_CHARS]
                if len(vuln_code) > _MAX_CODE_CHARS:
                    snip += "\n// ... [truncated]"
                block += f"\n\nVulnerable pattern:\n```solidity\n{snip}\n```"

            if fixed_code and fixed_code != "nan":
                snip = fixed_code[:_MAX_CODE_CHARS]
                if len(fixed_code) > _MAX_CODE_CHARS:
                    snip += "\n// ... [truncated]"
                block += f"\n\nFixed pattern:\n```solidity\n{snip}\n```"

            parts.append(block)

        return "\n\n---\n\n".join(parts)
