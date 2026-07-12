"""Flag a tool that returns or processes external/web content without
untrustedContentHint set.

Chrome's WebMCP security guidance treats content a tool pulls in from
outside the page (a fetched page, scraped text, another user's content) as
untrusted the moment it reaches the agent, because it can carry its own
injected instructions. Marking untrustedContentHint lets the calling agent
treat the result as data instead of directives.
"""

from __future__ import annotations

import re

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-002"
_I = re.IGNORECASE

# (pattern, severity). HIGH for phrasing that hands back raw/uncurated
# content the agent will read directly; MEDIUM for phrasing that merely
# reaches out to fetch something.
_PATTERNS = (
    (re.compile(r"\breturns?\s+(?:raw\s+)?html\b", _I), Severity.HIGH),
    (re.compile(r"\buser[\s-]generated\s+content\b", _I), Severity.HIGH),
    (re.compile(r"\buser\s+content\b", _I), Severity.HIGH),
    (re.compile(r"\bthird[\s-]party\s+content\b", _I), Severity.HIGH),
    (re.compile(r"\bscrapes?\b", _I), Severity.MEDIUM),
    (re.compile(r"\bcrawls?\b", _I), Severity.MEDIUM),
    (re.compile(r"\bfetch(?:es|ing|ed)?\s+(?:a\s+|the\s+)?(?:web\s?page|page|url|website|site|content)\b", _I), Severity.MEDIUM),
    (re.compile(r"\breads?\s+(?:a\s+|the\s+)?(?:web\s?page|page|website|url)\b", _I), Severity.MEDIUM),
    (re.compile(r"\bretrieves?\s+(?:a\s+|the\s+)?(?:web\s?page|page|url|website|content)\b", _I), Severity.MEDIUM),
    (re.compile(r"\bdownloads?\s+(?:a\s+|the\s+)?(?:file|page|content|url)\b", _I), Severity.MEDIUM),
    (re.compile(r"\bparses?\s+html\b", _I), Severity.MEDIUM),
    (re.compile(r"\bexternal\s+(?:content|data|website|page)\b", _I), Severity.MEDIUM),
    (re.compile(r"\bsearch(?:es)?\s+the\s+web\b", _I), Severity.MEDIUM),
    (re.compile(r"\bqueries?\s+(?:a\s+|the\s+)?(?:web|internet|search\s+engine)\b", _I), Severity.MEDIUM),
)


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        if tool.annotations.get("untrustedContentHint") is True:
            continue
        text = f"{tool.name} {tool.description}"
        best_sev = None
        best_match = ""
        for rx, sev in _PATTERNS:
            m = rx.search(text)
            if m and (best_sev is None or sev > best_sev):
                best_sev = sev
                best_match = m.group(0)
        if best_sev is None:
            continue
        label = tool.name or f"tool #{tool.index}"
        findings.append(mk(
            RULE_ID, Category.UNTRUSTED, best_sev, manifest.relpath,
            "Handles external content without untrustedContentHint",
            f'"{label}" reads as handling outside content ("{best_match.strip()}") but '
            "annotations.untrustedContentHint is not true. Whatever it returns can carry "
            "its own instructions aimed at the agent.",
            "Set annotations.untrustedContentHint to true so callers treat the result as "
            "data, not directives.",
            tool=tool.name, tool_index=tool.index,
        ))
    return findings
