"""Flag a tool whose name or description implies it runs arbitrary commands,
code, or queries. Exposed to an agent, that capability turns any successful
prompt injection into remote code execution.
"""

from __future__ import annotations

import re

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-005"
TITLE = "Arbitrary command or code execution"
SUMMARY = (
    "A tool name or description that reads as running arbitrary commands, "
    "code, SQL, or queries, which turns any successful injection into RCE."
)
_I = re.IGNORECASE

# "any query" alone is how a search box describes itself, so it only counts
# after a verb that runs the query.
_DANGER_TEXT = re.compile(
    r"\barbitrary\s+(?:shell\s+|system\s+)?(?:command|commands|code|script|scripts|sql|query|queries)\b"
    r"|\bany\s+(?:shell\s+|system\s+)?(?:command|commands|code|script|scripts|sql)\b"
    r"|\b(?:run|runs|running|execute|executes|executing|exec|eval|evaluate|evaluates|evaluating)"
    r"\s+any\s+(?:\w+\s+)?(?:query|queries)\b", _I)
_DANGER_NAME = re.compile(
    r"runshell|runcommand|run_command|shellexec|exec_?shell|execute(?:command|code|shell|script)", _I)
_DANGER_WORD = re.compile(r"^(?:exec|eval|shell)$", _I)
# "system" alone is getSystemStatus or setSystemTheme. Next to one of these
# words it is runSystemCommand.
_SYSTEM_PARTNERS = frozenset(("command", "commands", "cmd", "exec", "execute", "call", "script", "shell"))
# Split camelCase and snake/kebab case into words so systemExec and doEval
# count the same as system_exec, without matching "eval" inside "evaluation".
_WORD_SPLIT = re.compile(r"[^a-zA-Z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def _name_words(name: str) -> list:
    return [w for w in _WORD_SPLIT.split(name) if w]


def _dangerous_name(name: str) -> bool:
    if _DANGER_NAME.search(name):
        return True
    words = [w.lower() for w in _name_words(name)]
    if any(_DANGER_WORD.match(w) for w in words):
        return True
    return "system" in words and any(w in _SYSTEM_PARTNERS for w in words)


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        name = tool.name
        description = tool.description
        if not (_DANGER_TEXT.search(description) or _dangerous_name(name)):
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
