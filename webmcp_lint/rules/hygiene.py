"""Manifest hygiene: not a security hole by itself, but a manifest with
missing names, missing descriptions, duplicate tool names, or no tools at
all is hard to trust or reason about, and duplicate names actively collide
in whatever registry the agent resolves tools through.
"""

from __future__ import annotations

from collections import Counter

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-007"


def check(manifest) -> list:
    findings = []
    if manifest.parse_error or manifest.structure_error:
        return findings  # schema.py already reported the structural problem

    if not manifest.tools:
        findings.append(mk(
            RULE_ID, Category.HYGIENE, Severity.INFO, manifest.relpath,
            "Manifest declares no tools",
            "The tool list is empty, so there is nothing here for an agent to call.",
            "Add at least one tool, or remove the manifest if it is unused.",
        ))
        return findings

    for tool in manifest.tools:
        label = tool.name or f"tool #{tool.index}"
        if not tool.name:
            findings.append(mk(
                RULE_ID, Category.HYGIENE, Severity.LOW, manifest.relpath,
                "Tool has no name",
                f'Tool #{tool.index} has no "name" (or it is not a string), '
                "so an agent has nothing stable to call it by.",
                "Give every tool a short, unique, machine-stable name.",
                tool=tool.name, tool_index=tool.index,
            ))
        if not tool.description:
            findings.append(mk(
                RULE_ID, Category.HYGIENE, Severity.LOW, manifest.relpath,
                "Tool has no description",
                f'"{label}" has no "description" (or it is not a string), '
                "leaving an agent nothing to reason about before calling it.",
                "Write a plain description of what the tool does and when to use it.",
                tool=tool.name, tool_index=tool.index,
            ))

    names = [t.name for t in manifest.tools if t.name]
    dupes = sorted({n for n, c in Counter(names).items() if c > 1})
    for name in dupes:
        findings.append(mk(
            RULE_ID, Category.HYGIENE, Severity.LOW, manifest.relpath,
            "Duplicate tool name",
            f'"{name}" is declared more than once. Agents resolve tools by name, '
            "so one definition will shadow the other.",
            "Give each tool a unique name.",
            tool=name,
        ))
    return findings
