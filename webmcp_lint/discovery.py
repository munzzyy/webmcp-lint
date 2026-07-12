"""Resolve a command-line target to the manifest file(s) to scan.

The target can be a literal file, a directory (in which case we look for
the conventional manifest filenames inside it), or a glob pattern. Glob
expansion happens here rather than relying on the shell, so this also works
on Windows and with a quoted pattern.
"""

from __future__ import annotations

import glob as _glob
from pathlib import Path

# Filenames a WebMCP manifest conventionally lives at, checked in order.
WELL_KNOWN_NAMES = ("mcp.json", "webmcp.json", ".well-known/mcp.json")


def resolve_targets(target: str) -> list:
    p = Path(target)
    if p.is_file():
        return [p]
    if p.is_dir():
        return [p / name for name in WELL_KNOWN_NAMES if (p / name).is_file()]
    matches = sorted(_glob.glob(target, recursive=True))
    return [Path(m) for m in matches if Path(m).is_file()]
