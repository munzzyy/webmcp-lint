"""Turn findings into a security letter grade.

The score starts at 100 and loses points per security finding by severity.
Three hard caps encode the opinions that matter. A manifest that could not
be read at all is an F with a score of zero, because no rule inspected it
and a scan that inspected nothing must never produce a passing grade. Any
unresolved CRITICAL means "do not publish this manifest" (also F). Any HIGH
keeps it out of the top band (at most C). Hygiene and size-budget findings
do not affect the security grade.
"""

from __future__ import annotations

from .finding import Severity, SECURITY_CATEGORIES

_WEIGHT = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 15,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def grade(findings) -> tuple[str, int]:
    if any(getattr(f, "not_scanned", False) for f in findings):
        return "F", 0
    sec = [f for f in findings if f.category in SECURITY_CATEGORIES]
    score = 100
    n_crit = n_high = 0
    for f in sec:
        score -= _WEIGHT.get(f.severity, 0)
        if f.severity == Severity.CRITICAL:
            n_crit += 1
        elif f.severity == Severity.HIGH:
            n_high += 1
    score = max(0, min(100, score))

    if n_crit:
        return "F", score
    if n_high:
        score = min(score, 76)  # keep out of the A/B band
    return _letter(score), score


def _letter(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"
