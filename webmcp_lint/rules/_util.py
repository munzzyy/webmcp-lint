"""Shared Finding constructor and small helpers for rule modules."""

from __future__ import annotations

from ..finding import Category, Finding, Severity

# The annotations a WebMCP or MCP tool is allowed to carry. WebMCP itself
# defines readOnlyHint and untrustedContentHint; the other three come from
# the MCP core tool spec and turn up in tools/list dumps.
KNOWN_ANNOTATIONS = (
    "readOnlyHint",
    "untrustedContentHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)


def mk(
    rule_id: str,
    category: Category,
    severity: Severity,
    file: str,
    title: str,
    detail: str,
    remediation: str,
    tool: str = "",
    tool_index: int = -1,
    not_scanned: bool = False,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        detail=detail,
        file=file,
        tool=tool,
        tool_index=tool_index,
        remediation=remediation,
        not_scanned=not_scanned,
    )


def annotation_state(annotations, key: str) -> str:
    """One of "true", "false", "absent", or "wrongtype".

    Rules compare annotations against the boolean `True`, which is right: a
    JSON string "true" does not mean the same thing to a parser. But the
    author who wrote "true" did set the annotation, and telling them it is
    missing sends them looking for a key that is already there.
    """
    if not isinstance(annotations, dict) or key not in annotations:
        return "absent"
    value = annotations[key]
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "wrongtype"


def typename(v) -> str:
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
