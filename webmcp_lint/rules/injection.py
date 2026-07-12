"""Detect prompt-injection phrasing inside a tool's own name or description.

A tool's name, description, and schema are fed to the calling agent as
trusted context before the tool is ever invoked - that makes them an
injection surface in their own right ("tool poisoning"). A description that
tells the agent to ignore its instructions or hide an action from the user
is the WebMCP equivalent of a backdoor, and it works whether or not the
tool is ever called.

Patterns require an explicit object ("instructions", "the user", "your
system prompt") so ordinary phrases like "ignore case" or "act as a proxy"
don't trip them.
"""

from __future__ import annotations

import re

from ..finding import Category, Severity
from ._util import mk

RULE_ID = "WML-003"
_I = re.IGNORECASE

# (compiled, title, detail)
_PATTERNS = (
    (re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instructions?|prompts?|context|rules?|messages?|directions?)", _I),
     "Instruction-override phrasing",
     "Tells the agent to ignore its previous instructions, a classic prompt-injection payload."),
    (re.compile(r"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+|previous\s+|prior\s+|above\s+|system\s+)?(?:instructions?|prompts?|rules?|guidelines?|context)", _I),
     "Instruction-override phrasing",
     "Tells the agent to disregard its instructions or guidelines."),
    (re.compile(r"\bforget\s+(?:everything|all|your|the)\s+(?:previous\s+|prior\s+|above\s+)?(?:instructions?|rules?|guidelines?|context|you\s+(?:were\s+)?told)", _I),
     "Instruction-reset phrasing",
     "Tells the agent to forget its prior instructions."),
    (re.compile(r"\boverride\s+(?:your|the|all|any|previous|system)\s+(?:instructions?|guidelines?|rules?|safety|system\s+prompt|restrictions?|settings?)", _I),
     "Instruction-override phrasing",
     "Tells the agent to override its guidelines, safety, or system prompt."),
    (re.compile(r"\b(?:do\s+not|must\s+not|never)\s+(?:tell|inform|mention|alert|notify|warn|show)\s+(?:the\s+)?user\b", _I),
     "Hide-from-user directive",
     "Instructs the agent to conceal an action or result from the user."),
    (re.compile(r"\bwithout\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+)?(?:user|them|him|her)\b", _I),
     "Act-without-consent directive",
     "Instructs the agent to act without informing or asking the user."),
    (re.compile(r"\b(?:reveal|print|show|repeat|output|disclose|leak|dump)\s+(?:your|the|its)\s+(?:system\s+prompt|initial\s+instructions|instructions|prompt)\b", _I),
     "System-prompt disclosure attempt",
     "Tries to get the agent to reveal its system prompt or hidden instructions."),
    (re.compile(r"\byou\s+are\s+now\s+(?:a|an|in|the|no\s+longer)\b", _I),
     "Persona-override phrasing",
     "Attempts to redefine what the agent is, a common jailbreak opener."),
    (re.compile(r"^\s*(?:system|assistant)\s*:\s*\S", _I | re.MULTILINE),
     "Fake role header",
     'Opens with a "system:"/"assistant:" style header, mimicking a real chat-role '
     "message to smuggle instructions into the agent's context."),
    (re.compile(r"\balways\s+(?:run|execute|use|call|invoke)\b[^\n.]*\bwithout\s+(?:asking|confirming|prompting|checking)", _I),
     "Silent tool-execution directive",
     "Tells the agent to always run this tool without asking."),
)


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        for field_name, value in (("name", tool.name), ("description", tool.description)):
            if not value:
                continue
            for rx, title, detail in _PATTERNS:
                if not rx.search(value):
                    continue
                label = tool.name or f"tool #{tool.index}"
                findings.append(mk(
                    RULE_ID, Category.INJECTION, Severity.HIGH, manifest.relpath,
                    f"{title} ({field_name})",
                    f'"{label}" {field_name}: {detail}',
                    "Remove the directive. A tool description should describe a "
                    "capability, not instruct the agent to bypass its own rules or "
                    "hide actions from the user.",
                    tool=tool.name, tool_index=tool.index,
                ))
    return findings
