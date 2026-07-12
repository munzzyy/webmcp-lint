"""Schema and manifest-structure validity: malformed JSON, a manifest that
isn't a recognized tool list, and per-tool inputSchema problems.

Every other rule reads manifest.tools, so a manifest that fails to parse or
has no usable tools array needs a clear finding here rather than silently
scanning nothing.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-006"

# Keys that give a schema a shape without a "type" key of its own.
_SCHEMA_ESCAPE_KEYS = ("allOf", "anyOf", "oneOf", "$ref", "const", "enum")


def check(manifest) -> list:
    findings = []
    if manifest.parse_error:
        findings.append(mk(
            RULE_ID, Category.SCHEMA, Severity.MEDIUM, manifest.relpath,
            "Manifest is not valid JSON",
            f"The manifest could not be parsed: {manifest.parse_error}",
            "Fix the JSON syntax so the manifest can be read by a browser or agent.",
        ))
        return findings

    if manifest.structure_error:
        findings.append(mk(
            RULE_ID, Category.SCHEMA, Severity.MEDIUM, manifest.relpath,
            "Manifest is not a recognized WebMCP tool list",
            manifest.structure_error,
            'The manifest must be a JSON array of tools, or an object with a "tools" array.',
        ))
        return findings

    for tool in manifest.tools:
        if not tool.has_input_schema:
            continue
        label = tool.name or f"tool #{tool.index}"
        spec = tool.input_schema
        if not isinstance(spec, dict):
            findings.append(mk(
                RULE_ID, Category.SCHEMA, Severity.MEDIUM, manifest.relpath,
                "inputSchema is not an object",
                f'"{label}" has an inputSchema that is {_typename(spec)}, not a JSON object, '
                "so it cannot constrain arguments at all.",
                'Make inputSchema a JSON Schema object, e.g. {"type": "object", "properties": {...}}.',
                tool=tool.name, tool_index=tool.index,
            ))
            continue
        if "type" not in spec and not any(k in spec for k in _SCHEMA_ESCAPE_KEYS):
            findings.append(mk(
                RULE_ID, Category.SCHEMA, Severity.LOW, manifest.relpath,
                "inputSchema is missing a type",
                f'"{label}" has an inputSchema with no "type" and no allOf/anyOf/oneOf/$ref/const/enum, '
                "so its shape is unconstrained.",
                'Add "type": "object" (or the appropriate JSON Schema type) to inputSchema.',
                tool=tool.name, tool_index=tool.index,
            ))
    return findings


def _typename(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "a boolean"
    if isinstance(v, list):
        return "an array"
    if isinstance(v, str):
        return "a string"
    if isinstance(v, (int, float)):
        return "a number"
    return type(v).__name__
