"""Flag a risky-named parameter that is a free-form string with no
constraint (enum/const/format/pattern/maxLength) and no composite schema.

A parameter named "command" or "url" that accepts any string at all is a
payload channel: whatever steers the agent's argument choice steers what
actually runs, or where a request goes.

The whole schema is walked, not only its top level. Nesting request
parameters inside an options object or a batch array is ordinary API design,
and an unconstrained "command" in there is reachable exactly the same way.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ._schema_walk import iter_parameters
from ._util import mk

RULE_ID = "WML-004"
TITLE = "Unconstrained risky-named parameter"
SUMMARY = (
    "A parameter named command, sql, url, path and similar that accepts a "
    "free-form string with no enum, const, format, pattern, maxLength, or "
    "composite schema, at any depth in the inputSchema."
)

# A hostile schema can declare the same risky parameter hundreds of times.
# Report enough to act on and say how many were left.
MAX_PER_TOOL = 20

RISKY_PARAMS = frozenset({
    "command", "cmd", "code", "script", "exec", "sql", "query", "path", "file",
    "url", "endpoint", "host", "redirect", "callback", "prompt", "template",
    "html", "payload",
})


def is_freeform_string(spec) -> bool:
    if not isinstance(spec, dict):
        return False
    has_composite = any(isinstance(spec.get(k), list) for k in ("allOf", "anyOf", "oneOf"))
    # A schema with no "type" and no composite keyword accepts any JSON
    # value, strings included, so an untyped risky param is just as
    # free-form as an explicit string one.
    untyped = "type" not in spec and not has_composite
    t = spec.get("type")
    is_string = t == "string" or (isinstance(t, list) and "string" in t) or untyped
    if not is_string:
        return False
    constrained = (
        "enum" in spec or "const" in spec or "format" in spec or "pattern" in spec
        or isinstance(spec.get("maxLength"), (int, float)) or has_composite
    )
    return not constrained


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        label = tool.name or f"tool #{tool.index}"
        seen = set()
        reported = 0
        skipped = 0
        for pointer, pname, spec in iter_parameters(tool.input_schema):
            if pname.lower() not in RISKY_PARAMS or pointer in seen:
                continue
            if not is_freeform_string(spec):
                continue
            seen.add(pointer)
            if reported >= MAX_PER_TOOL:
                skipped += 1
                continue
            reported += 1
            # Say where it is. "command" three objects down is a different
            # fix from "command" at the top level.
            where = f" at {pointer}" if pointer != f"inputSchema.properties.{pname}" else ""
            findings.append(mk(
                RULE_ID, Category.RISKY_PARAM, Severity.MEDIUM, manifest.relpath,
                f'Unconstrained "{pname}" parameter',
                f'"{label}" takes "{pname}"{where} as a free-form string with no enum, format, '
                "pattern, or maxLength. Parameter names like this often carry command, "
                "path, or URL payloads, so the agent can be steered into passing something "
                "dangerous.",
                "Constrain the parameter: an enum of allowed values, a format/pattern, "
                "a maxLength, or a narrower composite schema.",
                tool=tool.name, tool_index=tool.index,
            ))
        if skipped:
            findings.append(mk(
                RULE_ID, Category.RISKY_PARAM, Severity.MEDIUM, manifest.relpath,
                "More unconstrained risky parameters than shown",
                f'"{label}" has {skipped} further unconstrained risky parameter(s) beyond '
                f"the first {MAX_PER_TOOL} reported.",
                "Constrain them the same way, then rerun to see the rest.",
                tool=tool.name, tool_index=tool.index,
            ))
    return findings
