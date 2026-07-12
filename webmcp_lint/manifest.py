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
    description: str  # "" if missing or not a string
    annotations: dict  # {} if missing or not an object
    has_input_schema: bool  # True only if the "inputSchema" key is present at all
    input_schema: Any  # whatever was under inputSchema; only meaningful if has_input_schema


@dataclass
class Manifest:
    path: Path
    relpath: str
    text: str = ""
    parse_error: str = ""  # set if the file could not be read/decoded/parsed as JSON
    structure_error: str = ""  # set if the JSON parsed but isn't a recognized tool list
    tools: list = field(default_factory=list)  # list[Tool]
    oversized: bool = False  # bigger than MAX_FILE_BYTES; only the prefix was read

    @property
    def ok(self) -> bool:
        return not self.parse_error and not self.structure_error


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

    try:
        m.text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        m.parse_error = f"file is not valid UTF-8: {e}"
        return m

    try:
        data = json.loads(m.text)
    except json.JSONDecodeError as e:
        m.parse_error = f"invalid JSON: {e}"
        return m

    tools_raw, err = _extract_tools(data)
    if err:
        m.structure_error = err
        return m

    m.tools = [_normalize_tool(i, t) for i, t in enumerate(tools_raw)]
    return m


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
        description=description,
        annotations=annotations,
        has_input_schema=has_input_schema,
        input_schema=input_schema,
    )
