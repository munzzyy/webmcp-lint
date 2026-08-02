"""Walk a tool's inputSchema so rules can see past the top level.

Two rules need the same traversal, so it lives here once.

A JSON Schema's per-property `description` is handed to the model verbatim
with the rest of the tool definition, which makes it an injection surface in
its own right, and hiding a payload one level down is the obvious way around
a scanner that only reads the tool's own description. A risky parameter
nested inside an options object or an array item is reachable in exactly the
same way a top-level one is.

The walk is depth-capped and visits each schema object once. A manifest is
untrusted input, and SECURITY.md counts hanging the linter as a
vulnerability, so a self-referential schema has to terminate.
"""

from __future__ import annotations

MAX_DEPTH = 12

# Keys whose value is a mapping of name -> subschema.
_MAP_KEYS = ("properties", "patternProperties", "definitions", "$defs")
# Keys whose value is a subschema, or a list of subschemas.
_SUB_KEYS = (
    "items", "additionalItems", "additionalProperties", "contains",
    "propertyNames", "not", "if", "then", "else",
    "allOf", "anyOf", "oneOf",
)
# Only these carry real parameter names; patternProperties keys are regexes.
_NAMED = ("properties",)


def walk(schema, root: str = "inputSchema"):
    """Yield (pointer, param_name, subschema) for every schema object.

    `param_name` is the declared property name when the subschema came from a
    `properties` map, otherwise "". `pointer` is a dotted path from the tool,
    e.g. inputSchema.properties.options.properties.command.
    """
    if not isinstance(schema, dict):
        return
    yield from _walk(schema, root, "", 0, set())


def _walk(node, pointer, param_name, depth, seen):
    if not isinstance(node, dict) or depth > MAX_DEPTH:
        return
    marker = id(node)
    if marker in seen:
        return
    seen.add(marker)

    yield pointer, param_name, node

    for key in _MAP_KEYS:
        mapping = node.get(key)
        if not isinstance(mapping, dict):
            continue
        for name, child in mapping.items():
            if not isinstance(name, str):
                continue
            child_name = name if key in _NAMED else ""
            yield from _walk(child, f"{pointer}.{key}.{name}", child_name, depth + 1, seen)

    for key in _SUB_KEYS:
        child = node.get(key)
        if isinstance(child, dict):
            yield from _walk(child, f"{pointer}.{key}", "", depth + 1, seen)
        elif isinstance(child, list):
            for i, item in enumerate(child):
                yield from _walk(item, f"{pointer}.{key}[{i}]", "", depth + 1, seen)


def iter_schema_text(schema, root: str = "inputSchema"):
    """Yield (pointer, text) for every `title`/`description` in the schema.

    The pointer names the exact field, so a finding can tell the author where
    to look: inputSchema.properties.q.description.
    """
    for pointer, _name, node in walk(schema, root):
        for key in ("title", "description"):
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                yield f"{pointer}.{key}", value


def tool_text_fields(tool):
    """Yield (label, text) for every string on a tool the model will read.

    That is the tool's own name, title and description, plus every title and
    description inside its inputSchema. Labels double as the pointer a
    finding quotes, so the author knows which field to open.
    """
    for label, value in (("name", tool.name), ("title", tool.title),
                         ("description", tool.description)):
        if value:
            yield label, value
    for pointer, value in iter_schema_text(tool.input_schema):
        yield pointer, value


def iter_parameters(schema, root: str = "inputSchema"):
    """Yield (pointer, param_name, subschema) for every declared property."""
    for pointer, name, node in walk(schema, root):
        if name:
            yield pointer, name, node
