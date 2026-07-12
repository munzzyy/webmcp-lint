"""Detect hidden or deceptive Unicode in a tool's own name or description:
bidirectional control characters (Trojan Source, CVE-2021-42574), invisible
Unicode tag characters (U+E0000-U+E007F), and zero-width characters. All
three are established ways to smuggle instructions past a human reviewer
while an agent reading the raw text still sees them.

Codepoints are referenced by integer and rendered with chr() only when
building a finding message, so this file's own source stays plain ASCII.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-008"

_INVISIBLE = {
    0x200B: "zero-width space",
    0x200C: "zero-width non-joiner",
    0x200D: "zero-width joiner",
    0x2060: "word joiner",
    0xFEFF: "zero-width no-break space (BOM)",
    0x00AD: "soft hyphen",
    0x2061: "function application",
    0x2062: "invisible times",
    0x2063: "invisible separator",
    0x2064: "invisible plus",
}
_BIDI = {
    0x202A: "left-to-right embedding",
    0x202B: "right-to-left embedding",
    0x202C: "pop directional formatting",
    0x202D: "left-to-right override",
    0x202E: "right-to-left override",
    0x2066: "left-to-right isolate",
    0x2067: "right-to-left isolate",
    0x2068: "first strong isolate",
    0x2069: "pop directional isolate",
}


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _scan(text: str) -> list:
    hits = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0xFEFF and i == 0:
            continue  # a leading BOM is benign
        if _is_tag_char(cp):
            hits.append((f"U+{cp:04X}", "invisible Unicode tag character"))
        elif cp in _BIDI:
            hits.append((f"U+{cp:04X}", f"bidirectional control character ({_BIDI[cp]})"))
        elif cp in _INVISIBLE:
            hits.append((f"U+{cp:04X}", f"invisible character ({_INVISIBLE[cp]})"))
    return hits


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        for field_name, value in (("name", tool.name), ("description", tool.description)):
            hits = _scan(value)
            if not hits:
                continue
            label = tool.name or f"tool #{tool.index}"
            shown = ", ".join(f"{cp} ({desc})" for cp, desc in hits[:5])
            more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
            findings.append(mk(
                RULE_ID, Category.UNICODE, Severity.HIGH, manifest.relpath,
                f"Hidden Unicode in tool {field_name}",
                f'"{label}" has hidden or deceptive Unicode in its {field_name}: '
                f"{shown}{more}. These characters are invisible or reorder how text "
                "renders, the standard way to smuggle instructions past a human "
                "reviewer while an agent still reads them.",
                "Remove the invisible/bidi characters from the field.",
                tool=tool.name, tool_index=tool.index,
            ))
    return findings
