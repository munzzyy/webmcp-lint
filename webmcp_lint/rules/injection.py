"""Detect prompt-injection phrasing inside a tool's own text.

A tool's name, description, and schema are fed to the calling agent as
trusted context before the tool is ever invoked - that makes them an
injection surface in their own right ("tool poisoning"). A description that
tells the agent to ignore its instructions or hide an action from the user
is the WebMCP equivalent of a backdoor, and it works whether or not the
tool is ever called.

The scan covers name, title and description, and every `description` and
`title` inside inputSchema. Those per-parameter strings ship to the model
with the rest of the tool definition, so dropping the payload one level down
is the cheapest way around a scanner that only reads the tool description,
and it is what most published tool-poisoning proofs of concept actually do.

Patterns require an explicit object ("instructions", "the user", "your
system prompt") so ordinary phrases like "ignore case" or "act as a proxy"
don't trip them.
"""

from __future__ import annotations

import re
import unicodedata

from ..finding import Category, Severity
from ._schema_walk import tool_text_fields
from ._util import mk

RULE_ID = "WML-003"
TITLE = "Prompt injection in a tool's own text"
SUMMARY = (
    "A tool name, title, description, or a description inside inputSchema "
    "that instructs the agent to ignore its instructions, hide an action from "
    "the user, reveal its system prompt, or adopt a new persona."
)
_I = re.IGNORECASE
# Fold everything except letters, digits, and ':' to a single space. The colon
# is kept literal because the fake-role-header pattern below matches on it
# ("system:"); every other separator (underscores, punctuation, whitespace
# runs) is noise an attacker can hide a phrase behind.
# Fold every separator run to a single space EXCEPT newlines, which are kept
# literal. A phrase pattern's \s+ still crosses a literal newline, so a payload
# wrapped across a line break is caught; and the role-header anchor can pin a
# "system:" header to the start of any line. The colon is kept for that anchor.
_SEPARATORS = re.compile(r"[^A-Za-z0-9:\n]+")

# A GENUINE sentence boundary: end punctuation followed by whitespace/quote.
# Folding collapses separators, but a phrase pattern's \s+ must not be allowed
# to bridge two unrelated *sentences* - so we split on real sentence boundaries
# first, fold each piece, then rejoin with a sentinel \s+ can't cross. A bare
# newline is NOT a sentence boundary (it's ordinary wrapping an attacker can
# drop mid-phrase), so it never becomes this wall.
#
# The split point is the whole separator run around each "end punctuation +
# space" pair. One regex starting with [^A-Za-z0-9:]* finds the same runs but
# rescans a long run of punctuation from every position in it, and a
# description of "/* " repeated took minutes.
_SEPARATOR_RUN = re.compile(r"[^A-Za-z0-9:]+")
_STOP_THEN_SPACE = re.compile(r"[.!?][\s\"')\]]")
_SENTINEL = "\x00"


def _sentences(text: str) -> list:
    pieces, last = [], 0
    n = len(text)
    backwards = None
    for stop in _STOP_THEN_SPACE.finditer(text):
        at = stop.start()
        if at < last:
            continue
        if backwards is None:
            backwards = text[::-1]
        start = n - _SEPARATOR_RUN.match(backwards, n - 1 - at).end()
        pieces.append(text[last:start])
        last = _SEPARATOR_RUN.match(text, at).end()
    pieces.append(text[last:])
    return pieces


class _SilentRunDirective:
    """"always run ... without asking" with any gap that stays on one line.

    As a single regex this needs an unbounded gap, and then every "always
    run" on a line rescans the rest of it: a 1.6 MB description of them ran
    for hours. Bounding the gap would let padding slip a directive through.
    So: for the first opener on each line, is there a closer later on that
    line? Each line is scanned once, and a closer found once is reused.
    """

    _OPEN = re.compile(r"\balways\s+(?:run|execute|use|call|invoke)\b", re.IGNORECASE)
    _CLOSE = re.compile(r"\bwithout\s+(?:asking|confirming|prompting|checking)", re.IGNORECASE)
    _BREAK = re.compile(r"[\n.]")

    def search(self, text: str):
        checked_to = -1
        closer = None
        for m in self._OPEN.finditer(text):
            if m.end() <= checked_to:
                continue
            brk = self._BREAK.search(text, m.end())
            line_end = brk.start() if brk else len(text)
            if closer is None or closer.start() < m.end():
                closer = self._CLOSE.search(text, m.end())
                if closer is None:
                    return None
            if closer.start() < line_end:
                return m
            checked_to = line_end
        return None


# (matcher, title, detail). Public because the aggregate rule (WML-010)
# re-runs the same set over joined and decoded text. A matcher is a compiled
# regex or anything else with the same search(text) method.
PATTERNS = (
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
    (re.compile(r"(?:^|\x00|\n)\s*(?:system|assistant)\s*:\s*\S", _I),
     "Fake role header",
     'Opens with a "system:"/"assistant:" style header, mimicking a real chat-role '
     "message to smuggle instructions into the agent's context."),
    (_SilentRunDirective(),
     "Silent tool-execution directive",
     "Tells the agent to always run this tool without asking."),
)


def fold_for_matching(text: str) -> str:
    """Collapse Unicode look-alikes and separator noise before matching.

    NFKC maps "compatibility" variants - fullwidth letters, an ideographic
    space, ligatures - down to their ordinary ASCII form, so a phrase spelled
    in fullwidth Unicode reads the same to the regex as the plain-ASCII one.
    Folding every non-alphanumeric run (underscores included, colon
    excepted) to a single space closes the other bypass: swapping spaces for
    underscores or punctuation still reads fine to an agent but used to
    slide past a \\s+-only pattern outright.

    Genuine sentence boundaries (end punctuation + whitespace) are preserved as
    a sentinel the phrase patterns' \\s+ can't span, so a pattern can't weld two
    unrelated sentences ("...you can safely ignore. Previous instructions...")
    into a false hit. A bare newline is left as a literal newline instead: \\s+
    still crosses it - so a payload wrapped across a line break ("ignore all
    previous\\ninstructions") is still caught, not silently dropped - while the
    fake-role-header anchor still pins a "system:" header to the start of any
    line, not only the first.

    This folded copy is used ONLY to decide whether a pattern matches -
    findings still report the tool's original, unmodified name/description.
    """
    normalized = unicodedata.normalize("NFKC", text)
    segments = (_SEPARATORS.sub(" ", seg) for seg in _sentences(normalized))
    return _SENTINEL.join(segments)


def check(manifest) -> list:
    findings = []
    for tool in manifest.tools:
        for field_name, value in tool_text_fields(tool):
            haystack = fold_for_matching(value)
            for rx, title, detail in PATTERNS:
                if not rx.search(haystack):
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
