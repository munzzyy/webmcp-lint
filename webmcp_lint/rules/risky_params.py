"""Flag a risky-named parameter that is a free-form string with no
constraint (enum/const/format/pattern/maxLength) and no composite schema.

A parameter named "command" or "url" that accepts any string at all is a
payload channel: whatever steers the agent's argument choice steers what
actually runs, or where a request goes.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-004"

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
        schema = tool.input_schema
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties")
        if not isinstance(props, dict):
            continue
        for pname, spec in props.items():
            if not isinstance(pname, str) or pname.lower() not in RISKY_PARAMS:
                continue
            if not is_freeform_string(spec):
                continue
            label = tool.name or f"tool #{tool.index}"
            findings.append(mk(
                RULE_ID, Category.RISKY_PARAM, Severity.MEDIUM, manifest.relpath,
                f'Unconstrained "{pname}" parameter',
                f'"{label}" takes "{pname}" as a free-form string with no enum, format, '
                "pattern, or maxLength. Parameter names like this often carry command, "
                "path, or URL payloads, so the agent can be steered into passing something "
                "dangerous.",
                "Constrain the parameter: an enum of allowed values, a format/pattern, "
                "a maxLength, or a narrower composite schema.",
                tool=tool.name, tool_index=tool.index,
            ))
    return findings
