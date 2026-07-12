"""Flag a read-shaped tool name that isn't marked readOnlyHint.

A name that reads like a lookup (getBalance, list_orders, search) sets an
agent's expectation that calling it is safe to retry and safe to call
speculatively. Without readOnlyHint set, an orchestrating agent has no
machine-readable way to confirm that, and has to fall back on guessing from
the name alone - exactly the mismatch this rule catches.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-001"

READ_VERBS = ("get", "list", "read", "search", "fetch", "view", "query")


def is_read_shaped(name: str) -> bool:
    """True if `name` starts with a read verb at a word boundary.

    Boundary-aware for camelCase (getBalance) and snake_case (get_balance),
    but a longer word in the same case is not a boundary, so "getting" and
    "reader" are not read-shaped. When the name has no lowercase letters at
    all (GETUSER), only a non-letter separator counts as a boundary, since
    a bare case flip isn't available to mark one.
    """
    if not name:
        return False
    lower = name.lower()
    has_lower = any(c.islower() for c in name)
    for verb in READ_VERBS:
        if not lower.startswith(verb):
            continue
        rest = name[len(verb):]
        if rest == "":
            return True
        first = rest[0]
        boundary = (not first.islower()) if has_lower else (not first.isalpha())
        if boundary:
            return True
    return False


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        if not tool.name or not is_read_shaped(tool.name):
            continue
        if tool.annotations.get("readOnlyHint") is True:
            continue
        findings.append(mk(
            RULE_ID, Category.READONLY, Severity.MEDIUM, manifest.relpath,
            "Read-shaped name is not marked read-only",
            f'"{tool.name}" reads like a lookup but annotations.readOnlyHint is not '
            "set to true. If it only reads data, agents lose the ability to treat it "
            "as safe to retry or call speculatively; if it mutates state, the name is misleading.",
            "Set annotations.readOnlyHint to true if the tool truly only reads data, "
            "otherwise rename it so it doesn't read as a lookup.",
            tool=tool.name, tool_index=tool.index,
        ))
    return findings
