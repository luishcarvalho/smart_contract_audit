"""Terminal display helpers (banner, hr, LLM response preview)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict


def hr(char: str = "=", n: int = 88) -> str:
    return char * n


def banner(title: str, char: str = "=") -> None:
    print("\n" + hr(char))
    print(title)
    print(hr(char))


# ─── LLM response preview ────────────────────────────────────────────────────

def _extract_llm_text(response: Dict[str, Any]) -> str:
    """Extract a representative string from a pipeline response dict."""
    if response is None:
        return ""

    for key in ("response", "final", "output_text", "text", "answer"):
        val = response.get(key)
        if isinstance(val, str) and val.strip():
            return val

    val = response.get("json_output")
    if isinstance(val, str) and val.strip():
        return val

    parsed = response.get("parsed_response")
    if parsed is not None:
        try:
            if hasattr(parsed, "model_dump"):
                return json.dumps(parsed.model_dump(), ensure_ascii=False, indent=2)
            if hasattr(parsed, "dict"):
                return json.dumps(parsed.dict(), ensure_ascii=False, indent=2)
            if isinstance(parsed, dict):
                return json.dumps(parsed, ensure_ascii=False, indent=2)
            return str(parsed)
        except Exception:
            return str(parsed)

    try:
        return json.dumps(response, ensure_ascii=False)
    except Exception:
        return str(response)


def _format_preview(text: str, *, max_chars: int = 700, max_lines: int = 12) -> str:
    if not text:
        return "(no textual preview available)"

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)

    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append("...[TRUNCATED LINES]")

    preview = "\n".join(lines)
    if max_chars and len(preview) > max_chars:
        preview = preview[:max_chars] + " ...[TRUNCATED CHARS]"

    return preview


def print_llm_preview(
    response: Dict[str, Any],
    *,
    title: str = "LLM RESPONSE PREVIEW",
    max_chars: int = 700,
    max_lines: int = 12,
) -> None:
    text = _extract_llm_text(response)
    preview = _format_preview(text, max_chars=max_chars, max_lines=max_lines)
    print("\n" + hr("-"))
    print(title)
    print(hr("-"))
    for ln in preview.split("\n"):
        print(f"   {ln}")
    print(hr("-"))
