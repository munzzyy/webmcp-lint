"""Scan orchestration: load each manifest, run every rule, aggregate, grade."""

from __future__ import annotations

from pathlib import Path

from .finding import ScanResult
from .grade import grade
from .manifest import load
from .rules import run_all


def scan_files(paths, root: str = "", ignore=()) -> ScanResult:
    """Scan every path and grade the result.

    `ignore` is a set of rule ids to drop. Filtering happens here rather than
    at print time so the grade and the exit code agree with what the user
    sees: a suppressed rule is suppressed everywhere.
    """
    ignored = {r.strip().upper() for r in ignore if r.strip()}
    result = ScanResult(root=root or ", ".join(str(p) for p in paths))
    result.manifests = len(paths)
    for p in paths:
        m = load(Path(p))
        result.scanned_files += 1
        result.tools += len(m.tools)
        result.findings.extend(
            f for f in run_all(m) if f.rule_id.upper() not in ignored)
    result.findings.sort(key=lambda f: f.sort_key())
    result.grade, result.grade_score = grade(result.findings)
    return result
