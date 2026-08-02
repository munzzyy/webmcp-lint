"""Flag text that blows Chrome's published WebMCP size budgets.

Chrome's secure-tools guidance gives tool authors hard character budgets: 30
for a tool name and for a parameter name, 500 for a tool description, 150 for
a parameter description. Going over is not only a style problem. Content past
the budget can be cut before the agent ever sees it, so a description can
read clean in review and carry something else past the cut, and a reviewer
who scrolls to the end of a 4,000-character description is reviewing text the
agent may never read in that form.

These are size-budget findings, not security ones, so they do not move the
security grade on their own.
"""

from __future__ import annotations

from ..finding import Category, Severity
from ._schema_walk import iter_parameters, iter_schema_text
from ._util import mk

RULE_ID = "WML-009"
TITLE = "Over Chrome's published size budget"
SUMMARY = (
    "A tool or parameter name over 30 characters, a tool description over 500, "
    "or a parameter description over 150. Text past the budget can be "
    "truncated before the agent reads it."
)

NAME_BUDGET = 30
TOOL_DESCRIPTION_BUDGET = 500
PARAM_DESCRIPTION_BUDGET = 150

_TRUNCATION_NOTE = (
    "Anything past the budget can be cut before the agent reads it, so what "
    "a reviewer reads and what the agent acts on stop being the same text."
)


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        label = tool.name or f"tool #{tool.index}"
        if len(tool.name) > NAME_BUDGET:
            findings.append(_over(
                manifest, tool, Severity.LOW, "Tool name is over the 30-character budget",
                f'"{label}" has a {len(tool.name)}-character name, over Chrome\'s '
                f"{NAME_BUDGET}-character budget for a tool name.",
                f"Shorten the name to {NAME_BUDGET} characters or fewer.",
            ))
        if len(tool.description) > TOOL_DESCRIPTION_BUDGET:
            findings.append(_over(
                manifest, tool, Severity.MEDIUM,
                "Tool description is over the 500-character budget",
                f'"{label}" has a {len(tool.description)}-character description, over '
                f"Chrome's {TOOL_DESCRIPTION_BUDGET}-character budget. {_TRUNCATION_NOTE}",
                f"Cut the description to {TOOL_DESCRIPTION_BUDGET} characters or fewer.",
            ))

        for pointer, pname, _spec in iter_parameters(tool.input_schema):
            if len(pname) > NAME_BUDGET:
                findings.append(_over(
                    manifest, tool, Severity.LOW,
                    "Parameter name is over the 30-character budget",
                    f'"{label}" declares "{pname}" at {pointer}, a {len(pname)}-character '
                    f"parameter name, over Chrome's {NAME_BUDGET}-character budget.",
                    f"Shorten the parameter name to {NAME_BUDGET} characters or fewer.",
                ))

        for pointer, text in iter_schema_text(tool.input_schema):
            if not pointer.endswith(".description"):
                continue
            if len(text) <= PARAM_DESCRIPTION_BUDGET:
                continue
            findings.append(_over(
                manifest, tool, Severity.MEDIUM,
                "Parameter description is over the 150-character budget",
                f'"{label}" has a {len(text)}-character description at {pointer}, over '
                f"Chrome's {PARAM_DESCRIPTION_BUDGET}-character budget. {_TRUNCATION_NOTE}",
                f"Cut it to {PARAM_DESCRIPTION_BUDGET} characters or fewer.",
            ))
    return findings


def _over(manifest, tool, severity, title, detail, fix):
    return mk(
        RULE_ID, Category.BUDGET, severity, manifest.relpath,
        title, detail, fix,
        tool=tool.name, tool_index=tool.index,
    )
