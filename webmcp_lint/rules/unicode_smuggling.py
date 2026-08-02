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
from ._schema_walk import tool_text_fields
from ._util import mk

RULE_ID = "WML-008"
TITLE = "Hidden or deceptive characters in a tool's own text"
SUMMARY = (
    "Bidirectional control characters, invisible Unicode tag characters, "
    "zero-width characters, or raw control/escape characters in a tool name, "
    "title, description, or a description inside inputSchema."
)

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


# Whitespace a JSON string legitimately carries: tab, newline, CR.
_ALLOWED_CONTROL = (0x09, 0x0A, 0x0D)


def _is_tag_char(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _control_label(cp: int) -> str:
    if cp == 0x1B:
        return "ESC, the start of a terminal escape sequence"
    if cp == 0x7F:
        return "delete"
    if cp >= 0x80:
        return "C1 control character"
    return "C0 control character"


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
        elif cp in _ALLOWED_CONTROL:
            continue
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            hits.append((f"U+{cp:04X}", f"control character ({_control_label(cp)})"))
    return hits


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        for field_name, value in tool_text_fields(tool):
            hits = _scan(value)
            if not hits:
                continue
            label = tool.name or f"tool #{tool.index}"
            shown = ", ".join(f"{cp} ({desc})" for cp, desc in hits[:5])
            more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
            findings.append(mk(
                RULE_ID, Category.UNICODE, Severity.HIGH, manifest.relpath,
                f"Hidden characters in {field_name}" if "." in field_name
                else f"Hidden characters in tool {field_name}",
                f'"{label}" has hidden or deceptive characters in its {field_name}: '
                f"{shown}{more}. These are invisible, reorder how text renders, or "
                "drive the terminal directly - the standard ways to smuggle "
                "instructions past a human reviewer while an agent still reads them.",
                "Remove the invisible, bidi, and control characters from the field.",
                tool=tool.name, tool_index=tool.index,
            ))
    return findings
