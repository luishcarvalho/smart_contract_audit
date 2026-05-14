"""VulnDescLookup: maps vulnerability names to canonical descriptions from CSV."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import pandas as pd


# Aliases for semantic mismatches not resolved by normalized string matching
_ALIASES: Dict[str, List[str]] = {
    "arithmetic":                                   ["integer overflow and underflow"],
    "bad randomness":                               ["weak sources of randomness from chain attributes"],
    "unsafe delegatecall":                          ["delegatecall to untrusted callee"],
    "direct call to untrusted contract":            ["delegatecall to untrusted callee"],
    "denial of service":                            ["dos with failed call", "dos with block gas limit"],
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


def _norm(s: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]", "", s.lower().strip()))


class VulnDescLookup:
    """Look up canonical vulnerability descriptions by vulnerability name."""

    def __init__(self, df: pd.DataFrame) -> None:
        self._index: Dict[str, str] = {}
        for _, row in df.iterrows():
            key = _norm(str(row["vulnerability"]))
            self._index[key] = str(row["description"])

    @classmethod
    def from_csv(cls, path: str) -> "VulnDescLookup":
        return cls(pd.read_csv(path))

    def _find_description(self, normalized: str) -> Optional[str]:
        # 1. Exact match after normalization
        if normalized in self._index:
            return self._index[normalized]

        # 2. Hardcoded aliases for semantic mismatches
        alias_targets = _ALIASES.get(normalized, [])
        for target in alias_targets:
            for key, desc in self._index.items():
                if target in key or key in target:
                    return desc

        # 3. Substring containment (handles minor wording differences)
        for key, desc in self._index.items():
            if normalized in key or key in normalized:
                return desc

        return None

    def lookup(self, vulnerability_name: str) -> str:
        """Return the canonical description for *vulnerability_name*, or '' if no match."""
        desc = self._find_description(_norm(vulnerability_name))
        return desc if desc is not None else ""
