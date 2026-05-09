"""Binary classification metrics for (contract, vulnerability) pairs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return _safe_div(2 * p * r, p + r)

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return _safe_div(self.tp + self.tn, total)

    def __add__(self, other: "Metrics") -> "Metrics":
        return Metrics(
            tp=self.tp + other.tp,
            fp=self.fp + other.fp,
            tn=self.tn + other.tn,
            fn=self.fn + other.fn,
        )

    def as_dict(self) -> Dict[str, float]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
        }


def _safe_div(num: float, den: float) -> float:
    return num / den if den != 0 else 0.0


def classify_pair(
    ground_truth_vuln: str,
    target_vuln: str,
    predicted_vulns: list[str],
) -> Metrics:
    """Return binary TP/FP/TN/FN for one (contract, target vulnerability) pair.

    ground_truth_vuln  : the vulnerability label on the contract
    target_vuln        : the vulnerability we asked the LLM to detect
    predicted_vulns    : issue names extracted from the LLM JSON output
    """
    gt_lower = ground_truth_vuln.lower()
    tgt_lower = target_vuln.lower()
    is_gt_positive = gt_lower == tgt_lower

    preds_lower = [str(v).lower() for v in predicted_vulns]
    is_pred_positive = any(
        (tgt_lower in p) or (p in tgt_lower) for p in preds_lower
    )

    if is_gt_positive and is_pred_positive:
        return Metrics(tp=1)
    elif is_gt_positive and not is_pred_positive:
        return Metrics(fn=1)
    elif not is_gt_positive and is_pred_positive:
        return Metrics(fp=1)
    else:
        return Metrics(tn=1)
