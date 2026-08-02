"""Flag a manifest that still points at navigator.modelContext.

WebMCP moved its registration surface from `navigator.modelContext` to
`document.modelContext` in May 2026, and Chrome's own docs say plainly that
navigator.modelContext is deprecated as of Chrome 150. Tools registered only
on the old surface stop being visible to the agent once the origin trial
ends, which is a silent failure: the page looks fine and exposes nothing.

What this rule can see today is the manifest text, so it catches the old API
name wherever it appears in the file: a description, a docs link, an example
snippet, a build-time export that recorded the call site. It cannot see a
site's JavaScript, because webmcp-lint reads JSON. Scanning JS and HTML
source for registerTool call sites is the roadmap item that closes that gap;
until then this is the part that is checkable, and it is worth checking.
"""

from __future__ import annotations

import re

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-011"
TITLE = "Deprecated navigator.modelContext registration surface"
SUMMARY = (
    "The manifest references navigator.modelContext, deprecated in Chrome "
    "150. Tools registered only there stop being exposed after the origin "
    "trial; document.modelContext is the current surface."
)

_DEPRECATED = re.compile(r"\bnavigator\s*\.\s*modelContext\b")


def check(manifest) -> list:
    text = getattr(manifest, "text", "") or ""
    if not _DEPRECATED.search(text):
        return []
    return [mk(
        RULE_ID, Category.SCHEMA, Severity.MEDIUM, manifest.relpath,
        "References the deprecated navigator.modelContext API",
        "This manifest names navigator.modelContext. WebMCP moved registration to "
        "document.modelContext, and Chrome deprecated the navigator surface in "
        "Chrome 150, so tools registered only there stop being exposed to the "
        "agent when the origin trial ends.",
        "Register on document.modelContext instead, and update any docs or "
        "examples in the manifest that still name navigator.modelContext.",
    )]
