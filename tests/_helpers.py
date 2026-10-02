"""Shared test helpers."""

from __future__ import annotations

import atexit
import json
import shutil
import tempfile
from pathlib import Path

from webmcp_lint.finding import Category
from webmcp_lint.scanner import scan_files

_ROOT = tempfile.mkdtemp(prefix="wml-test-")
atexit.register(shutil.rmtree, _ROOT, ignore_errors=True)


def temp_dir() -> Path:
    """A fresh directory, removed with all the others when the test run exits."""
    return Path(tempfile.mkdtemp(dir=_ROOT))


def scan_tools(tools: list):
    """Write `tools` as a manifest array to a temp file and scan it."""
    return scan_manifest({"tools": tools})


def scan_manifest(data):
    """Write `data` (already the full manifest JSON, array or object) to a
    temp file and scan it."""
    path = temp_dir() / "mcp.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return scan_files([path], root=str(path))


def scan_raw(text: str):
    """Write literal `text` (may be invalid JSON) to a temp file and scan it."""
    path = temp_dir() / "mcp.json"
    path.write_text(text, encoding="utf-8")
    return scan_files([path], root=str(path))


def by_cat(result, cat: Category):
    return [f for f in result.findings if f.category == cat]


def by_rule(result, rule_id: str):
    return [f for f in result.findings if f.rule_id == rule_id]


def titles(result):
    return [f.title for f in result.findings]
