"""Flag a tool whose name or description implies it runs arbitrary commands,
code, or queries. Exposed to an agent, that capability turns any successful
prompt injection into remote code execution.
"""

from __future__ import annotations

import re

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-005"
_I = re.IGNORECASE

_DANGER_TEXT = re.compile(
    r"\b(?:arbitrary|any)\s+(?:shell\s+|system\s+)?(?:command|commands|code|script|scripts|sql|query|queries)\b", _I)
_DANGER_NAME = re.compile(
    r"runshell|runcommand|run_command|shellexec|exec_?shell|execute(?:command|code|shell|script)", _I)
_DANGER_WORD = re.compile(r"^(?:exec|eval|shell|system)$", _I)
# Split camelCase and snake/kebab case into words so systemExec and doEval
# count the same as system_exec, without matching "eval" inside "evaluation".
_WORD_SPLIT = re.compile(r"[^a-zA-Z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def _name_words(name: str) -> list:
    return [w for w in _WORD_SPLIT.split(name) if w]


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        name = tool.name
        description = tool.description
        words = _name_words(name)
        hit = bool(
            _DANGER_TEXT.search(description)
            or _DANGER_NAME.search(name)
            or any(_DANGER_WORD.match(w) for w in words)
        )
        if not hit:
            continue
        label = name or f"tool #{tool.index}"
        findings.append(mk(
            RULE_ID, Category.EXEC, Severity.HIGH, manifest.relpath,
            "Exposes arbitrary command or code execution",
            f'"{label}" reads as running arbitrary commands, code, or queries. Exposed '
            "to an agent, any successful prompt injection becomes remote code execution.",
            "Constrain the tool to specific, named operations instead of an open executor.",
            tool=name, tool_index=tool.index,
        ))
    return findings
