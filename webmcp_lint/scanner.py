"""Scan orchestration: load each manifest, run every rule, aggregate, grade."""

from __future__ import annotations

from pathlib import Path

from .finding import ScanResult
from .grade import grade
from .manifest import load
from .rules import run_all


def scan_files(paths, root: str = "") -> ScanResult:
    result = ScanResult(root=root or ", ".join(str(p) for p in paths))
    result.manifests = len(paths)
    for p in paths:
        m = load(Path(p))
        result.scanned_files += 1
        result.tools += len(m.tools)
        result.findings.extend(run_all(m))
    result.findings.sort(key=lambda f: f.sort_key())
    result.grade, result.grade_score = grade(result.findings)
    return result
