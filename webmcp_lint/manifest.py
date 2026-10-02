"""Load a WebMCP tool manifest from disk and normalize the tools it declares.

A manifest is a JSON file shaped one of two ways: a bare array of tool
objects, or an object with a "tools" array (the shape a well-known/mcp.json
or an MCP tools/list response uses). Each tool looks like:

    {
      "name": "getWeather",
      "description": "...",
      "inputSchema": {"type": "object", "properties": {...}},
      "annotations": {"readOnlyHint": true}
    }

Loading never raises on bad input: a manifest that isn't valid JSON, or
JSON that isn't a recognized tool list, comes back as a Manifest with an
error string set instead of a traceback, so a rule can report it as a
finding rather than crash the whole scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# A manifest should be a handful of KB. Cap it so a hostile or malformed file
# can't make the linter read gigabytes into memory.
MAX_FILE_BYTES = 2_000_000

_MISSING = object()


@dataclass
class Tool:
    index: int  # position in the tools array, 0-based
    raw: dict  # the tool object as parsed ({} if the array entry wasn't an object)
    name: str  # "" if missing or not a string
    title: str  # "" if missing or not a string; a human-facing display label
    description: str  # "" if missing or not a string
    annotations: dict  # {} if missing or not an object
    has_input_schema: bool  # True only if the "inputSchema" key is present at all
    input_schema: Any  # whatever was under inputSchema; only meaningful if has_input_schema
    line: int = 0  # line of its registerTool( call in JS/HTML source, 0 for a JSON manifest


@dataclass
class Manifest:
    path: Path
    relpath: str
    text: str = ""
    parse_error: str = ""  # set if the file could not be read/decoded/parsed as JSON
    structure_error: str = ""  # set if the JSON parsed but isn't a recognized tool list
    tools: list = field(default_factory=list)  # list[Tool]
    oversized: bool = False  # bigger than MAX_FILE_BYTES; only the prefix was read
    too_deep: bool = False  # nested deeper than the JSON decoder can recurse
    source: bool = False  # read from JS/HTML source by jsextract, not a JSON manifest
    unread_calls: list = field(default_factory=list)  # (line, reason) per registerTool call jsextract could not read

    @property
    def ok(self) -> bool:
        return not self.parse_error and not self.structure_error



# Deeper than any manifest and shallower than any interpreter's parser stack,
# so a [[[[...]]]] file fails the same way on every Python; 3.14.0 parses
# 100,000 levels without a RecursionError, 3.14.7 does not.
MAX_JSON_DEPTH = 512


def _json_depth(text: str) -> int:
    depth = peak = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > peak:
                peak = depth
        elif ch in "]}":
            depth -= 1
    return peak

def load(path: Path) -> Manifest:
    m = Manifest(path=path, relpath=str(path))
    try:
        size = path.stat().st_size
    except OSError as e:
        m.parse_error = f"could not stat file: {e}"
        return m

    m.oversized = size > MAX_FILE_BYTES
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES)
    except OSError as e:
        m.parse_error = f"could not read file: {e}"
        return m

    # Only a prefix was read, so anything downstream would be judging a file
    # nobody actually looked at. Say that instead of letting json.loads blame
    # the author for a syntax error that isn't there.
    if m.oversized:
        m.parse_error = (
            f"file is larger than the {MAX_FILE_BYTES}-byte scan limit "
            f"({size} bytes), so it was not scanned"
        )
        return m

    text, decode_error = _decode(raw)
    if decode_error:
        m.parse_error = decode_error
        return m
    m.text = text

    if _json_depth(m.text) > MAX_JSON_DEPTH:
        m.too_deep = True
        m.parse_error = "the JSON is nested too deeply to parse"
        return m
    try:
        data = json.loads(m.text)
    except json.JSONDecodeError as e:
        m.parse_error = f"invalid JSON: {e}"
        return m
    except RecursionError:
        m.too_deep = True
        m.parse_error = "the JSON is nested too deeply to parse"
        return m

    tools_raw, err = _extract_tools(data)
    if err:
        m.structure_error = err
        return m

    m.tools = [_normalize_tool(i, t) for i, t in enumerate(tools_raw)]
    return m


_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def _decode(raw: bytes) -> tuple:
    """Decode manifest bytes to text, returning (text, error).

    utf-8-sig rather than utf-8: it is identical to utf-8 except that it
    strips a leading byte-order mark, which json.loads otherwise rejects as
    a syntax error. Notepad, PowerShell's Out-File and .NET's default
    encoder all write that BOM, and the manifest they wrote is fine.

    A UTF-16 BOM gets decoded as UTF-16 for the same reason: PowerShell
    redirection produces UTF-16LE by default, and telling that author their
    JSON is broken would be wrong twice over.
    """
    if raw[:2] in _UTF16_BOMS:
        try:
            return raw.decode("utf-16"), ""
        except UnicodeDecodeError as e:
            return "", ("file starts with a UTF-16 byte-order mark but is not "
                        f"valid UTF-16: {e}")
    try:
        return raw.decode("utf-8-sig"), ""
    except UnicodeDecodeError as e:
        return "", f"file is not valid UTF-8: {e}"


def _extract_tools(data) -> tuple:
    if isinstance(data, list):
        return data, ""
    if isinstance(data, dict):
        tools = data.get("tools")
        if isinstance(tools, list):
            return tools, ""
        if tools is not None:
            return [], 'the "tools" field is present but is not an array'
        return [], 'no top-level array and no "tools" array found'
    return [], 'manifest JSON must be an array of tools or an object with a "tools" array'


def _normalize_tool(index: int, raw) -> Tool:
    d = raw if isinstance(raw, dict) else {}
    name = d.get("name")
    name = name if isinstance(name, str) else ""
    title = d.get("title")
    title = title if isinstance(title, str) else ""
    description = d.get("description")
    description = description if isinstance(description, str) else ""
    annotations = d.get("annotations")
    annotations = annotations if isinstance(annotations, dict) else {}
    has_input_schema = "inputSchema" in d
    input_schema = d.get("inputSchema", _MISSING)
    if input_schema is _MISSING:
        input_schema = None
    return Tool(
        index=index,
        raw=d,
        name=name,
        title=title,
        description=description,
        annotations=annotations,
        has_input_schema=has_input_schema,
        input_schema=input_schema,
    )
