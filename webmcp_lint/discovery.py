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

# WebMCP has no manifest file in the spec, so most real sites have none of
# the names above and only ever call document.modelContext.registerTool(...)
# from a page's own script. These are the entry-file names a directory scan
# also checks, but only as a fallback (a JSON manifest always wins if one is
# found) and only when the file actually mentions registerTool, so a plain
# static site's index.html doesn't turn into a false "manifest not found"
# scan failure. See jsextract.py for what happens once one is picked up.
WELL_KNOWN_JS_NAMES = ("index.html", "index.htm", "mcp.js", "webmcp.js")

# Directories a recursive scan never descends into for manifests. These hold
# other projects' dependencies or build output, not the site's own tools.
_SKIP_DIR_NAMES = frozenset({
    "node_modules", ".git", "dist", "build", "venv", ".venv", "__pycache__", ".tox",
})


def _under_skip_dir(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts[:-1]  # directories only, not the filename
    return any(part in _SKIP_DIR_NAMES for part in parts)


def _rglob_files(root: Path, names) -> set:
    found = set()
    for name in names:
        for match in root.rglob(name):
            if match.is_file() and not _under_skip_dir(match, root):
                found.add(match)
    return found


def _looks_like_webmcp_source(path: Path) -> bool:
    """Cheap textual check, not a real parse: does this file mention
    registerTool at all? Used only to decide whether a fallback entry file
    is worth treating as a scan target, never to decide what it contains."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "registerTool" in text


def resolve_targets(target: str, recursive: bool = False) -> list:
    p = Path(target)
    if p.is_file():
        return [p]
    if p.is_dir():
        found = {p / name for name in WELL_KNOWN_NAMES if (p / name).is_file()}
        if recursive:
            found |= _rglob_files(p, WELL_KNOWN_NAMES)
        if not found:
            candidates = {p / name for name in WELL_KNOWN_JS_NAMES if (p / name).is_file()}
            if recursive:
                candidates |= _rglob_files(p, WELL_KNOWN_JS_NAMES)
            found = {c for c in candidates if _looks_like_webmcp_source(c)}
        return sorted(found, key=str)
    matches = sorted(_glob.glob(target, recursive=True))
    return [Path(m) for m in matches if Path(m).is_file()]
