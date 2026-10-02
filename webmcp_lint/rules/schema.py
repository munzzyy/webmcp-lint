"""Schema and manifest-structure validity: malformed JSON, a manifest that
isn't a recognized tool list, and per-tool inputSchema problems.

Every other rule reads manifest.tools, so a manifest that fails to parse or
has no usable tools array needs a clear finding here rather than silently
scanning nothing.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ..jsextract import describe_unread
from ._util import KNOWN_ANNOTATIONS, annotation_state, mk, typename

RULE_ID = "WML-006"
TITLE = "Schema and manifest-structure validity"
SUMMARY = (
    "The manifest is not valid JSON, is not a recognized tool list, is too "
    "large to scan, has an inputSchema that is not an object or has no type, "
    "or carries an annotation of the wrong JSON type."
)

# Keys that give a schema a shape without a "type" key of its own.
_SCHEMA_ESCAPE_KEYS = ("allOf", "anyOf", "oneOf", "$ref", "const", "enum")

_SOURCE_FIX = (
    "Pass registerTool a literal object, and keep name, description, "
    "inputSchema and annotations as literals so they can be checked. If the "
    "tools have to be built at runtime, lint a JSON export of the tool list instead."
)


def check(manifest) -> list:
    findings = []
    # A manifest nobody could read is the worst case for a linter: zero rules
    # ran, so every other check is silent and the report looks clean. It is
    # reported HIGH and marked not_scanned so the default gate fails and the
    # grade floors at F, rather than a broken file passing CI with an A.
    source = getattr(manifest, "source", False)
    if manifest.parse_error:
        oversized = getattr(manifest, "oversized", False)
        if oversized:
            fix = "Split the file so it fits under the scan limit."
        elif source:
            fix = "Make sure the file exists, is readable, and is saved as UTF-8."
        else:
            fix = "Fix the JSON syntax so the manifest can be read by a browser or agent."
        findings.append(mk(
            RULE_ID, Category.SCHEMA, Severity.HIGH, manifest.relpath,
            "Manifest too large to scan" if oversized else "Manifest is not valid JSON",
            f"The manifest could not be parsed, so no rule inspected it: {manifest.parse_error}",
            fix,
            not_scanned=True,
        ))
        return findings

    if manifest.structure_error:
        findings.append(mk(
            RULE_ID, Category.SCHEMA, Severity.HIGH, manifest.relpath,
            "Manifest is not a recognized WebMCP tool list",
            f"{manifest.structure_error}. No tools were found, so no rule inspected anything.",
            _SOURCE_FIX if source else
            'The manifest must be a JSON array of tools, or an object with a "tools" array.',
            not_scanned=True,
        ))
        return findings

    unread = getattr(manifest, "unread_calls", None)
    if unread:
        total = len(unread) + len(manifest.tools)
        findings.append(mk(
            RULE_ID, Category.SCHEMA, Severity.HIGH, manifest.relpath,
            "Some registerTool calls could not be read",
            f"{len(unread)} of the {total} registerTool(...) calls in this file could not "
            f"be read, so the tools they register were not checked: {describe_unread(unread)}.",
            _SOURCE_FIX,
            partial=True,
        ))

    for tool in manifest.tools:
        label = tool.name or f"tool #{tool.index}"
        findings.extend(_annotation_types(manifest, tool, label))
        if not tool.has_input_schema:
            continue
        spec = tool.input_schema
        if not isinstance(spec, dict):
            findings.append(mk(
                RULE_ID, Category.SCHEMA, Severity.MEDIUM, manifest.relpath,
                "inputSchema is not an object",
                f'"{label}" has an inputSchema that is {typename(spec)}, not a JSON object, '
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


def _annotation_types(manifest, tool, label: str) -> list:
    """A hint set to the string "true" is not set at all as far as a parser
    is concerned, and a template engine or a YAML-to-JSON step stringifying a
    boolean is a normal way to get there. Say so, instead of leaving the
    other rules to report the annotation as missing."""
    findings = []
    for key in KNOWN_ANNOTATIONS:
        if annotation_state(tool.annotations, key) != "wrongtype":
            continue
        value = tool.annotations[key]
        findings.append(mk(
            RULE_ID, Category.SCHEMA, Severity.LOW, manifest.relpath,
            f"Annotation {key} has the wrong type",
            f'"{label}" sets annotations.{key} to {typename(value)}, not a JSON boolean, '
            "so every consumer reads it as unset.",
            f"Write annotations.{key} as a JSON boolean: true or false, without quotes.",
            tool=tool.name, tool_index=tool.index,
        ))
    return findings
