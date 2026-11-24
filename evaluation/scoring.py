"""Shared scoring: CWE matching, confusion metrics, Wilson intervals."""

from __future__ import annotations

import math
import re

# A reported CWE counts for a case when it is in the same family as the case's CWE
# (e.g. Semgrep tags eval() as CWE-95; the OWASP code-injection category is CWE-94).
CWE_FAMILIES = [
    {22, 23, 36, 73},       # path traversal
    {77, 78},               # OS command injection
    {89},                   # SQL injection
    {79, 80},               # XSS
    {94, 95},               # code injection / eval
    {502},                  # deserialization
    {611, 776},             # XXE
    {327, 328, 916},        # weak hash / crypto
    {330, 338},             # weak randomness
    {601},                  # open redirect
]

MODES = ("file", "cwe", "cwe-strict")


def cwe_numbers(value) -> set[int]:
    """'CWE-89: Improper ...' or a list of such strings -> {89}."""
    items = value if isinstance(value, list) else [value]
    return {int(n) for item in items if item for n in re.findall(r"CWE-(\d+)", str(item))}


def family(cwe: int) -> set[int]:
    for fam in CWE_FAMILIES:
        if cwe in fam:
            return fam
    return {cwe}


def cwe_match(reported: set[int], expected: int, mode: str) -> bool:
    if mode == "file":
        return True
    if mode == "cwe-strict":
        return expected in reported
    return bool(reported & family(expected))


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def confusion(pairs: list[tuple[bool, bool]]) -> dict:
    """pairs = [(actually_vulnerable, predicted_vulnerable), ...]"""
    tp = sum(a and p for a, p in pairs)
    fp = sum(p and not a for a, p in pairs)
    tn = sum(not a and not p for a, p in pairs)
    fn = sum(a and not p for a, p in pairs)
    pos, neg = tp + fn, fp + tn
    recall = tp / pos if pos else None
    fpr = fp / neg if neg else None
    return {
        "n": len(pairs), "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "recall": recall,
        "false_positive_rate": fpr,
        "precision": tp / (tp + fp) if tp + fp else None,
        "accuracy": (tp + tn) / len(pairs) if pairs else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None,
        # OWASP Benchmark score: 0 = random guessing, 1 = perfect.
        "youden": recall - fpr if recall is not None and fpr is not None else None,
        "recall_ci95": wilson(tp, pos),
        "fpr_ci95": wilson(fp, neg),
    }


def pct(x) -> str:
    return "–" if x is None else f"{x * 100:.1f}%"


def pts(x) -> str:
    return "–" if x is None else f"{x * 100:+.1f}"


def ci(x) -> str:
    return "–" if not x else f"{x[0] * 100:.0f}–{x[1] * 100:.0f}%"
