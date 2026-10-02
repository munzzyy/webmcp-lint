"""Scan orchestration: load each manifest, run every rule, aggregate, grade."""

from __future__ import annotations

from pathlib import Path

from .finding import ScanResult
from .grade import grade
from .jsextract import JS_EXTENSIONS
from .jsextract import load as load_js
from .manifest import load as load_json
from .rules import run_all
from .rules.schema import crashed


def _load(path: Path):
    """Route a target to the manifest loader for its kind of file.

    A JS/HTML file has no manifest to parse as JSON at all, so it goes
    through the best-effort registerTool(...) extractor instead; everything
    else is read as a JSON manifest same as always.
    """
    if path.suffix.lower() in JS_EXTENSIONS:
        return load_js(path)
    return load_json(path)


def scan_files(paths, root: str = "", ignore=()) -> ScanResult:
    """Scan every path and grade the result.

    `ignore` is a set of rule ids to drop. Filtering happens here rather than
    at print time so the grade and the exit code agree with what the user
    sees: a suppressed rule is suppressed everywhere.

    One thing --ignore cannot suppress: a manifest, or a registerTool call
    in a source file, the linter could not read.
    Dropping that finding would turn a file nobody inspected into a clean A,
    which is the exact failure the not_scanned flag exists to prevent. A
    suppression switch must never be able to manufacture a passing verdict
    out of a scan that did not happen.
    """
    ignored = {r.strip().upper() for r in ignore if r.strip()}
    result = ScanResult(root=root or ", ".join(str(p) for p in paths))
    result.manifests = len(paths)
    for p in paths:
        path = Path(p)
        try:
            m = _load(path)
            found = run_all(m)
            tools = len(m.tools)
        except Exception as e:  # one hostile file must not end the run for the others
            found = [crashed(str(path), e)]
            tools = 0
        result.scanned_files += 1
        result.tools += tools
        result.findings.extend(
            f for f in found
            if f.not_scanned or f.partial or f.rule_id.upper() not in ignored)
    result.findings.sort(key=lambda f: f.sort_key())
    result.grade, result.grade_score = grade(result.findings)
    return result
