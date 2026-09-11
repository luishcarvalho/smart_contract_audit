"""Binary classification metrics for (contract, vulnerability) pairs."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, Iterable


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

    @property
    def specificity(self) -> float:
        """True Negative Rate = TN / (TN + FP)."""
        return _safe_div(self.tn, self.tn + self.fp)

    @property
    def balanced_accuracy(self) -> float:
        """Mean of recall (TPR) and specificity (TNR) — robust to class imbalance."""
        return (self.recall + self.specificity) / 2

    @property
    def mcc(self) -> float:
        """Matthews Correlation Coefficient — the recommended single-number score
        for heavily imbalanced binary classification. Range [-1, 1]; 0 = random."""
        num = (self.tp * self.tn) - (self.fp * self.fn)
        den = math.sqrt(
            (self.tp + self.fp)
            * (self.tp + self.fn)
            * (self.tn + self.fp)
            * (self.tn + self.fn)
        )
        return num / den if den != 0 else 0.0

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
            "specificity": self.specificity,
            "balanced_accuracy": self.balanced_accuracy,
            "mcc": self.mcc,
        }


def _safe_div(num: float, den: float) -> float:
    return num / den if den != 0 else 0.0


def _norm_label_set(labels: "str | Iterable[str]") -> set[str]:
    """Normalize one label or a collection of them into a set.

    A bare string stays one label — it is NOT split — so legacy single-label
    datasets keep behaving exactly as before.
    """
    if labels is None:
        return set()
    if isinstance(labels, str):
        return {_norm_label(labels)}
    return {_norm_label(l) for l in labels if str(l).strip()}


def _norm_label(s: str) -> str:
    """Normalize a vulnerability label for comparison: lowercase, collapse any
    run of non-alphanumeric characters to a single space, strip. Makes matching
    robust to punctuation/spacing differences between the test-set labels and the
    catalog vocabulary, without the false matches a substring test would allow."""
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


def classify_pair(
    ground_truth_vuln: "str | Iterable[str]",
    target_vuln: str,
    predicted_vulns: list[str],
) -> Metrics:
    """Return binary TP/FP/TN/FN for one (contract, target vulnerability) pair.

    ground_truth_vuln  : the label(s) on the contract — a single string, or any
                         iterable of strings for a multi-label ground truth
    target_vuln        : the vulnerability we asked the LLM to detect
    predicted_vulns    : issue names extracted from the LLM JSON output

    Both ground-truth and prediction are compared by NORMALIZED EXACT match
    (see _norm_label). The previous substring test could pair unrelated labels
    (e.g. "access control" ⊂ "access control bug"); normalized equality avoids
    those false matches while still tolerating punctuation/spacing differences.

    Multi-label: a file carrying several documented bugs is positive for EVERY
    one of its labels. With a single-label ground truth, detecting a second real
    bug of the same file scored as a false positive — 68.3% of the bugs in the
    current Web3Bugs extraction live in such files, so that mattered.
    """
    gt_norms = _norm_label_set(ground_truth_vuln)
    tgt_norm = _norm_label(target_vuln)
    is_gt_positive = tgt_norm in gt_norms

    preds_norm = {_norm_label(v) for v in predicted_vulns}
    is_pred_positive = tgt_norm in preds_norm

    if is_gt_positive and is_pred_positive:
        return Metrics(tp=1)
    elif is_gt_positive and not is_pred_positive:
        return Metrics(fn=1)
    elif not is_gt_positive and is_pred_positive:
        return Metrics(fp=1)
    else:
        return Metrics(tn=1)
