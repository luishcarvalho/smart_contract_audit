"""I/O helpers: JSON serialisation, embedding checkpoints."""
from __future__ import annotations

import json
import os
import pickle
from typing import Any, Dict, List, Optional


# ─── JSON ─────────────────────────────────────────────────────────────────────

def safe_json_dumps(obj: Any, max_chars: int = 20_000) -> str:
    """Serialise *obj* to JSON, truncating if needed. Never raises."""
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str)
        if max_chars and len(s) > max_chars:
            return s[:max_chars] + " ...[TRUNCATED]"
        return s
    except Exception:
        s = str(obj)
        return s[:max_chars] if max_chars else s


# ─── Embedding checkpoint ─────────────────────────────────────────────────────

def load_checkpoint(path: str) -> Optional[Dict[str, Any]]:
    """Return checkpoint dict or None if it doesn't exist / is corrupt."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def save_checkpoint(path: str, data: Dict[str, Any]) -> None:
    with open(path, "wb") as f:
        pickle.dump(data, f)


def completed_batch_indices(checkpoint: Optional[Dict[str, Any]]) -> List[int]:
    """Return list of already-processed batch indices from a checkpoint."""
    if checkpoint is None:
        return []
    return checkpoint.get("completed_batches", [])
