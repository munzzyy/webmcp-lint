"""Shared Finding constructor for rule modules."""

from __future__ import annotations

from ..finding import Category, Finding, Severity


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
    )
