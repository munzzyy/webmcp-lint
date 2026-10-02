"""Best-effort extraction of WebMCP tool definitions straight out of JS source.

WebMCP has no manifest file in the spec: a page registers each tool at
runtime with a call like:

    document.modelContext.registerTool({
      name: "getWeather",
      description: "...",
      inputSchema: {...},
      async execute({city}) {...},
    });

Most real sites never produce a JSON file at all, so a linter that only
reads JSON has nothing to scan on them. This module is NOT a JS parser. It
tokenizes the source once, so strings, template literals, comments and
regex literals are recognized and a brace or a "//" inside one of them is
not mistaken for code. Then it finds each registerTool( call and reads the
object literal passed to it. Literal values are kept and the `execute`
callback is dropped. Anything else (a variable, a spread, a function call,
a template literal with `${...}`, a computed key) makes that call site
unreadable.

An unreadable call site is never dropped quietly. scan_source() returns it
with its line number and the reason, load() records it on the Manifest, and
schema.py reports it as a HIGH finding. A file where no call could be read
at all is reported as not scanned.

A tokenizer has to guess at a few spots, mostly whether a "/" after "}"
starts a regex or divides. A wrong guess can turn the code after it into a
string or a comment, which would hide a call. So the text is also searched
for "registerTool(" directly, and a match the tokenizer did not read as a
call is reported as unread when it sits in a ${...}, in text the tokenizer
could not make sense of, or anywhere after the first guess. Before any
guess, a match inside a comment or a string really is one and is left alone.

An .html file is walked the way a browser's HTML tokenizer walks it:
comments end where a browser ends them, attribute values and the text of
<style>, <textarea> and the like are not markup, and a <script> runs to the
end tag a browser would stop at. Only <script> elements are read as code,
including <script> inside inline SVG. A "registerTool(" in an attribute
value (an onclick handler, a javascript: URL, a srcdoc) is reported as
unread. Inline SVG and MathML, <select> and <frameset> change how a browser
parses what comes after them in ways that depend on the whole document
tree; the walk follows the simple cases, and once it meets one it cannot
follow, every "registerTool(" from there to the end of the page that it did
not read as a call is reported as unread.

TypeScript and JSX go through the same tokenizer. Type annotations and
return types on the `execute` callback, type arguments on the call, and
`as` or `satisfies` after a literal value are skipped, and a method
signature such as `registerTool(tool: Tool): void` in an interface or class
is a definition, not a call. A "<" where a value should start can open JSX,
which the tokenizer does not parse, so it counts as a guess like the "/"
above.
"""

from __future__ import annotations

import html as _html
import re
from array import array
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from .manifest import MAX_FILE_BYTES, Manifest, _decode, _normalize_tool

# Extensions scan_files() routes through this module instead of manifest.py.
JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".html", ".htm")
_HTML_EXTENSIONS = (".html", ".htm")
_MODULE_EXTENSIONS = (".mjs", ".mts")
_TS_EXTENSIONS = (".ts", ".mts", ".cts", ".tsx")
# No JSX in these, so a "<" before a value is a type assertion or type parameters.
_NO_JSX_EXTENSIONS = (".ts", ".mts", ".cts")

_WS_RX = re.compile(
    r"[ \t\n\r\f\v\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+")
_LINE_BREAKS = ("\n", "\r", "\u2028", "\u2029")
_HAS_LINE_BREAK = re.compile(r"[\n\r\u2028\u2029]").search
_WS_CHARS = frozenset(" \t\n\r\f\v\u00a0\u1680\u202f\u205f\u3000\ufeff\u2028\u2029"
                      + "".join(map(chr, range(0x2000, 0x200b))))
_REST_OF_LINE_RX = re.compile(r"[^\n\r\u2028\u2029]*")
_STRING_STOP_RX = {'"': re.compile(r'["\\\n\r]'), "'": re.compile(r"['\\\n\r]")}
_TEMPLATE_STOP_RX = re.compile(r"[`\\]|\$\{")
_ID_ESCAPE = r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\})"
_IDENT_RX = re.compile(
    r"(?:[^\W\d]|\$|" + _ID_ESCAPE + r")(?:\w|\$|\u200c|\u200d|" + _ID_ESCAPE + r")*")
_ID_ESCAPE_RX = re.compile(r"\\u(?:([0-9a-fA-F]{4})|\{([0-9a-fA-F]+)\})")
_NUMBER_RX = re.compile(r"\.?[0-9](?:[\w.]|(?<=[eE])[+-])*")
_PUNCT_RX = re.compile(
    r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\|"
    r"|\?\?|\?\.(?![0-9])|\+\+|--|\*\*|[-+*%&|^]=|<<|>>|[{}()\[\];,<>+\-*%&|^!~?:=.@#]")
_DIVIDE_RX = re.compile(r"/=?")
_REGEX_FLAGS_RX = re.compile(r"\w*")
_ESCAPE_RX = re.compile(
    r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|[\s\S])")
_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
    "\n": "", "\r": "", "\r\n": "", "\u2028": "", "\u2029": "",
}


def _spelled(word: str) -> str:
    """A regex for `word` as JS source may spell it, each letter either
    plain or as a \\uXXXX or \\u{XX} escape."""
    def hexdigits(s):
        return "".join(f"[{d}{d.upper()}]" if d.isalpha() else d for d in s)
    return "".join(
        f"(?:{ch}|\\\\u{hexdigits(f'{ord(ch):04x}')}|\\\\u\\{{0*{hexdigits(f'{ord(ch):x}')}\\}})"
        for ch in word)


# Any spelling of a registerTool( call, wherever it sits. Not unregisterTool(.
_CALL_NAME = (
    r"(?<![\w$\u200c\u200d\\])" + _spelled("registerTool"))
_CANDIDATE_RX = re.compile(_CALL_NAME + r"\s*(?:\?\.\s*)?\(")
# TypeScript can put a non-null "!" or type arguments between the name and the "(".
_TS_CANDIDATE_RX = re.compile(_CALL_NAME + r"\s*(?:!\s*)?(?:\?\.\s*)?[(<]")

# After one of these keywords a "/" starts a regex. After any other word it divides.
_REGEX_AFTER_WORDS = frozenset((
    "return", "typeof", "instanceof", "in", "new", "delete", "void", "throw",
    "case", "do", "else", "default", "extends"))
# Keywords in one context and plain names in another, so a "/" after them is a guess.
_UNSURE_WORDS = frozenset(("yield", "await", "of"))
# No operand: a "/" after these or a break/continue label is a regex, but odd enough to be a guess.
_NO_OPERAND_WORDS = frozenset(("break", "continue", "debugger"))
_PAREN_KEYWORDS = frozenset(("if", "while", "for", "with"))
_BLOCK_WORDS = frozenset(("else", "do", "try", "finally", "static"))
# ASI can end the statement after these, so a "{" on the next line may open a block.
_LINE_END_WORDS = frozenset(("return", "yield", "await", "of"))
_LITERAL_KINDS = frozenset(("]", "S", "N", "T", "R"))
_ASI_KINDS = frozenset((None, ";", "{", "}", ")", "=>", "]", "S", "N", "T", "R", "X", "++", "--"))
_BRACE_CONTEXT = {"{b": "block", "{e": "expr", "{c": "class"}
# Before a bare registerTool( one of these means a value goes here, so it is a call.
# Not void, which also ends a member's return type on the line before.
_VALUE_WORDS = (_REGEX_AFTER_WORDS | _UNSURE_WORDS) - {"void"}
_MEMBER_STARTS = _LITERAL_KINDS | {"{", ",", ";", "}", ")"}
_ANGLE_CLOSERS = {">": 1, ">>": 2, ">>>": 3}

_OPENERS = frozenset(("(", "[", "{"))
_CLOSERS = {")": "(", "]": "[", "}": "{"}
_STOPS = frozenset((",", ")", "]", "}", "E"))
_KEY_STARTS = frozenset(("I", "S", "N", "["))

_FUNCTION = object()
_UNDEFINED = object()
_LITERAL_WORDS = {
    "true": True, "false": False, "null": None, "undefined": _UNDEFINED,
    "NaN": float("nan"), "Infinity": float("inf"),
}

# How many unreadable call sites a message lists before summarizing the rest.
_LIST_LIMIT = 10
# Far deeper than any real tool schema. Past it the call is reported unread
# instead of building a structure that deep out of hostile input.
MAX_NESTING = 100
_INF = float("inf")

_AFTER_SLASH = ('it follows a "/" that could be a regex or a division, so the scanner may '
                "have read it as part of a string or comment by mistake")
_AFTER_HTML_COMMENT = ('it follows a "<!--", which is a comment in a classic script but code '
                       "in a module, so the scanner may have read it as a comment by mistake")
_AFTER_JSX = ('it follows a "<" that could open JSX markup, which the scanner does not parse, '
              "so it may have read part of the markup as a string or comment by mistake")
_TYPE_ARGUMENTS = "the scanner could not find the end of its type arguments"
_UNTOKENIZED = "the scanner could not tokenize the code around it"
_IN_SUBSTITUTION = "it is inside a ${...} in a template literal"
_IN_ATTRIBUTE = "it is in an HTML attribute value, which the scanner does not read as code"
_UNFOLLOWED = ("it is outside any <script> the scanner could read, after SVG, MathML, "
               "<select> or <frameset> markup it cannot follow")


@dataclass
class CallSite:
    line: int  # 1-based line of the registerTool( call
    tool: object = None  # the tool dict, or None when the call could not be read
    problem: str = ""  # why it could not be read


class _Unreadable(Exception):
    pass


def scan_source(text: str, html: bool = False, module=None, ts: bool = False,
                jsx: bool = True) -> list:
    """Every registerTool(...) call site in `text`, readable or not, in order.

    `module` says whether JS is an ES module (True), a classic script
    (False) or unknown (None); it decides what "<!--" means. `ts` reads
    TypeScript type arguments and non-null "!", and `jsx` says whether a
    "<" before a value can open JSX.
    """
    if html:
        walk = _HtmlWalk(text)
        found = []
        for js, where, is_module in walk.sources:
            found.extend(_scan_js(js, where, is_module))
        found.extend((off, None, _IN_ATTRIBUTE) for off in walk.unread)
        if walk.uncertain < len(text):
            seen = {f[0] for f in found}
            for m in _CANDIDATE_RX.finditer(text, walk.uncertain):
                c = m.start()
                if c not in seen and not _within(walk.values, c):
                    found.append((c, None, _UNFOLLOWED))
    else:
        found = _scan_js(text, _shifted(0), module, ts, jsx)
    found.sort(key=lambda f: f[0])
    calls = []
    line, counted = 1, 0
    for off, tool, problem in found:
        line += text.count("\n", counted, off)
        counted = off
        calls.append(CallSite(line, tool, problem))
    return calls


def extract_tools(text: str, html: bool = False, ts: bool = False) -> list:
    """The tool dicts from every registerTool({...}) call that could be read."""
    return [c.tool for c in scan_source(text, html, ts=ts) if c.tool is not None]


def describe_unread(calls) -> str:
    """'line 3: why; line 9: why', for (line, problem) pairs or CallSites."""
    pairs = [(c.line, c.problem) if isinstance(c, CallSite) else c for c in calls]
    shown = "; ".join(f"line {line}: {problem}" for line, problem in pairs[:_LIST_LIMIT])
    if len(pairs) > _LIST_LIMIT:
        shown += f"; and {len(pairs) - _LIST_LIMIT} more"
    return shown


def _shifted(base: int):
    return lambda off: base + off


def _within(spans, c: int) -> bool:
    """Whether c falls inside one of `spans`, sorted non-overlapping (start, end) pairs."""
    i = bisect_right(spans, (c, _INF)) - 1
    return i >= 0 and c < spans[i][1]


def _scan_js(text: str, where, module, ts: bool = False, jsx: bool = True) -> list:
    """(page offset, tool or None, problem) for each call site in one piece
    of JS. `where` maps an offset in `text` to an offset in the page."""
    kinds, vals, starts, ends, subs, unsure, why_unsure, ctx = _tokenize(text, module, ts, jsx)
    kinds.extend(("E", "E", "E"))
    vals.extend((None, None, None))
    match = _match_brackets(kinds)
    out = []
    seen = set()
    angles = _match_angles(kinds) if ts else None
    for k, paren in _call_sites(kinds, vals, match, ctx, angles):
        seen.add(starts[k])
        if paren is None:
            out.append((where(starts[k]), None, _TYPE_ARGUMENTS))
            continue
        try:
            out.append((where(starts[k]), _read_call(kinds, vals, match, paren), ""))
        except _Unreadable as e:
            out.append((where(starts[k]), None, str(e)))
    for m in (_TS_CANDIDATE_RX if ts else _CANDIDATE_RX).finditer(text):
        c = m.start()
        if c in seen:
            continue
        problem = _missed(c, kinds, starts, ends, subs, unsure, why_unsure)
        if problem:
            out.append((where(c), None, problem))
    return out


def _missed(c, kinds, starts, ends, subs, unsure, why_unsure) -> str:
    """Why a registerTool( the call-site pass did not pick up must still be
    reported, or "" when it is a definition or sits in a real comment or string."""
    t = bisect_right(starts, c) - 1
    if t >= 0 and c < ends[t]:
        kind = kinds[t]
        if kind == "I":
            return ""
        if kind in ("X", "N"):
            return _UNTOKENIZED
        if kind == "T" and _within(subs, c):
            return _IN_SUBSTITUTION
    return why_unsure if c >= unsure else ""


def _tokenize(text: str, module=None, ts: bool = False, jsx: bool = True):
    """Split JS source into tokens in one linear pass.

    Returns parallel lists: kinds, values, start and end offsets. A
    punctuator's kind is its own text. Other kinds: "I" identifier (escapes
    decoded), "S" string, "T" template literal (value None when it has a
    ${...}), "N" number, "R" regex, "X" anything unrecognized. Tokens inside
    a ${...} are lexed but not emitted; the whole template comes out as one
    "T" token. Also returns the (start, end) of each ${...} in a top-level
    template, the offset of the first guess that could have gone wrong (or
    the text length) with the reason, and the enclosing context of each
    registerTool identifier token: "block", "expr" (an object literal),
    "class", "top" or "other".
    """
    kinds, vals = [], []
    starts, ends = array("l"), array("l")
    subs = []
    ctx = {}
    n = len(text)
    unsure, why_unsure = n, ""
    i = _REST_OF_LINE_RX.match(text, 2).end() if text.startswith("#!") else 0
    prev = prev_val = before = before_val = None
    dotted = paren_kw = colon_q = ended = False
    brace = "b"
    class_at = -1
    line_has_code = False
    # Open brackets, innermost last. "(k" heads if/while/for/with; "{b", "{e", "{c" open
    # a block, an object literal, a class body.
    stack = []
    open_q = [0]  # "?" still waiting for its ":", per open bracket
    templates = 0
    template_start = sub_start = -1
    regex_memo = [None]
    class_words = ("class", "interface") if ts else ("class",)

    while i < n:
        if stack and stack[-1] == "`":
            i, stop = _template_stop(text, i)
            if stop == "`":
                stack.pop()
                open_q.pop()
                templates -= 1
                if not templates:
                    kinds.append("T")
                    vals.append(None)
                    starts.append(template_start)
                    ends.append(i)
                before, before_val, prev, prev_val = prev, prev_val, "T", None
                dotted = paren_kw = colon_q = ended = False
            elif stop == "${":
                if templates == 1:
                    sub_start = i - 2
                stack.append("${")
                open_q.append(0)
                before, before_val, prev, prev_val = prev, prev_val, "(", None
                dotted = paren_kw = colon_q = ended = False
            continue

        c = text[i]
        start = i
        if c in _WS_CHARS:
            i = _WS_RX.match(text, i).end()
            if _HAS_LINE_BREAK(text, start, i):
                line_has_code = False
            continue
        nxt = text[i + 1:i + 2]
        if c == "/" and nxt == "/":
            i = _REST_OF_LINE_RX.match(text, i).end()
            continue
        if c == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            if _HAS_LINE_BREAK(text, i, end):
                line_has_code = False
            i = end
            continue
        if not module and ((c == "<" and text.startswith("<!--", i)) or (
                c == "-" and not line_has_code and text.startswith("-->", i))):
            if c == "<" and module is None and i < unsure:
                unsure, why_unsure = i, _AFTER_HTML_COMMENT
            i = _REST_OF_LINE_RX.match(text, i).end()
            continue

        if c in "\"'":
            end = _string_end(text, i, c)
            if end != -1:
                kind, val, i = "S", _cook(text[i + 1:end - 1]), end
            else:
                kind, val, i = "X", None, _REST_OF_LINE_RX.match(text, i + 1).end()
        elif c == "`":
            end, stop = _template_stop(text, i + 1)
            if stop == "`":
                raw = text[i + 1:end - 1].replace("\r\n", "\n").replace("\r", "\n")
                kind, val, i = "T", _cook(raw), end
            else:
                if not templates:
                    template_start = i
                stack.append("`")
                open_q.append(0)
                templates += 1
                if stop == "${":
                    if templates == 1:
                        sub_start = end - 2
                    stack.append("${")
                    open_q.append(0)
                    before, before_val, prev, prev_val = prev, prev_val, "(", None
                    dotted = paren_kw = colon_q = ended = False
                i = end
                continue
        elif "0" <= c <= "9" or (c == "." and "0" <= nxt <= "9"):
            m = _NUMBER_RX.match(text, i)
            kind, val, i = "N", _js_number(m.group()), m.end()
        elif c == "/":
            if ts and prev == "!":
                # x! / 2 divides after TypeScript's non-null "!"; !/re/ is a regex.
                postfix = before in _LITERAL_KINDS or before == ")" or (
                    before == "I" and before_val not in _VALUE_WORDS)
                regex, guess = not postfix, True
            else:
                regex, guess = _slash(prev, prev_val, dotted, paren_kw, brace, ended)
            if guess and i < unsure:
                unsure, why_unsure = i, _AFTER_SLASH
            end = _scan_regex(text, i, regex_memo) if regex else -1
            if end != -1:
                kind, val, i = "R", None, end
            else:
                m = _DIVIDE_RX.match(text, i)
                kind, val, i = m.group(), None, m.end()
        else:
            m = _IDENT_RX.match(text, i)
            if m:
                kind, val, i = "I", _ident(m.group()), m.end()
            else:
                m = _PUNCT_RX.match(text, i)
                if m:
                    kind, val, i = m.group(), None, m.end()
                else:
                    kind, val, i = "X", None, i + 1
                if (jsx and kind == "<" and start < unsure
                        and _slash(prev, prev_val, dotted, paren_kw, brace, ended)[0]):
                    unsure, why_unsure = start, _AFTER_JSX

        newline = not line_has_code
        line_has_code = True
        now_dotted = now_paren_kw = now_colon_q = now_ended = False
        now_brace = "b"
        if prev == "I" and prev_val in class_words and kind not in ("I", "{"):
            class_at = -1  # `{class: ...}` or `x.class(...)`: a name, not a class
        if kind == "I":
            now_dotted = prev in (".", "?.", "#")
            now_ended = not now_dotted and (val in _NO_OPERAND_WORDS or (
                ended and not newline and prev_val in ("break", "continue")))
            if val in class_words and not now_dotted:
                class_at = len(stack)
        elif kind == "(":
            kw = prev == "I" and not dotted and (
                prev_val in _PAREN_KEYWORDS
                or (prev_val == "await" and before == "I" and before_val == "for"))
            stack.append("(k" if kw else "(")
            open_q.append(0)
        elif kind == "[":
            stack.append("[")
            open_q.append(0)
        elif kind == "{":
            if class_at == len(stack):
                opened = "{c"
                class_at = -1
            else:
                opened = "{" + _brace_kind(prev, prev_val, dotted, colon_q,
                                           stack[-1] if stack else "", newline)
            stack.append(opened)
            open_q.append(0)
        elif kind in (")", "]", "}"):
            top = stack[-1] if stack else ""
            if kind == "}" and top == "${":
                stack.pop()
                open_q.pop()
                if templates == 1:
                    subs.append((sub_start, i))
                continue
            if top[:1] == _CLOSERS[kind]:
                stack.pop()
                open_q.pop()
                now_paren_kw = top == "(k"
                if kind == "}":
                    now_brace = top[1]
                if class_at > len(stack):
                    class_at = -1
        elif kind == "?":
            open_q[-1] += 1
        elif kind == ":":
            if open_q[-1]:
                open_q[-1] -= 1
                now_colon_q = True
        elif kind == ";" and class_at == len(stack):
            class_at = -1

        if not templates:
            if kind == "I" and val == "registerTool":
                ctx[len(kinds)] = _BRACE_CONTEXT.get(stack[-1], "other") if stack else "top"
            kinds.append(kind)
            vals.append(val)
            starts.append(start)
            ends.append(i)
        before, before_val, prev, prev_val = prev, prev_val, kind, val
        dotted, paren_kw, brace, colon_q = now_dotted, now_paren_kw, now_brace, now_colon_q
        ended = now_ended

    if templates:
        kinds.append("X")
        vals.append(None)
        starts.append(template_start)
        ends.append(n)
    return kinds, vals, starts, ends, subs, unsure, why_unsure, ctx


def _slash(prev, prev_val, dotted, paren_kw, brace, ended):
    """(does a "/" here start a regex, is that a guess)."""
    if prev is None:
        return True, False
    if prev == "I":
        if dotted:
            return False, False
        if prev_val in _REGEX_AFTER_WORDS:
            return True, False
        unsure = ended or prev_val in _UNSURE_WORDS
        return unsure, unsure
    if prev == ")":
        return paren_kw, False
    if prev == "}":
        # A regex after a block, a division after an object or a function expression.
        return brace != "e", True
    if prev in _LITERAL_KINDS:
        return False, False
    if prev in ("++", "--", "X"):
        return False, True
    return True, False


def _brace_kind(prev, prev_val, dotted, colon_q, top, newline) -> str:
    """"b" if a "{" after `prev` opens a block, "e" if an object literal."""
    if prev == ":":
        return "e" if colon_q or top in ("{e", "{c", "(", "(k", "[", "${") else "b"
    if prev in _ASI_KINDS:
        return "b"
    if prev == "I":
        if dotted or prev_val in _BLOCK_WORDS or (newline and prev_val in _LINE_END_WORDS):
            return "b"
        return "e" if prev_val in _REGEX_AFTER_WORDS or prev_val in _UNSURE_WORDS else "b"
    return "e"


def _ident(raw: str) -> str:
    if "\\" not in raw:
        return raw
    return _ID_ESCAPE_RX.sub(_ident_char, raw)


def _ident_char(m) -> str:
    digits = (m.group(1) or m.group(2)).lstrip("0")
    if len(digits) > 6 or int(digits or "0", 16) > 0x10FFFF:
        return "\ufffd"
    return chr(int(digits or "0", 16))


def _string_end(text: str, i: int, quote: str) -> int:
    """Index just past the string literal opening at i, or -1 if a line
    break or the end of the file comes first."""
    stop = _STRING_STOP_RX[quote]
    j = i + 1
    while True:
        m = stop.search(text, j)
        if m is None:
            return -1
        c = m.group()
        if c == quote:
            return m.end()
        if c != "\\":
            return -1
        j = m.end() + (2 if text.startswith("\r\n", m.end()) else 1)


def _template_stop(text: str, i: int):
    """From i inside template text, (index just past the next "`" or "${",
    which one it was), or (end of file, "") if neither comes."""
    while True:
        m = _TEMPLATE_STOP_RX.search(text, i)
        if m is None:
            return len(text), ""
        if m.group() != "\\":
            return m.end(), m.group()
        i = m.end() + 1


def _scan_regex(text: str, start: int, memo: list) -> int:
    """Index just past the regex literal whose "/" is at `start`, or -1.

    A scan that fails marks every (position, in-class) state it passed
    through, so a later attempt reaching one of them stops at once. Without
    that, a long line of unclosed "/[" would be rescanned from every slash.
    """
    failed = memo[0]
    n = len(text)
    p = start + 1
    in_class = False
    while p < n:
        bit = 2 if in_class else 1
        if failed is not None and failed[p] & bit:
            break
        c = text[p]
        if c in _LINE_BREAKS:
            break
        if c == "\\":
            if p + 1 < n and text[p + 1] in _LINE_BREAKS:
                break
            p += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            return _REGEX_FLAGS_RX.match(text, p + 1).end()
        p += 1

    if failed is None:
        failed = memo[0] = bytearray(n + 2)
    stop = p
    p = start + 1
    in_class = False
    while p < stop:
        failed[p] |= 2 if in_class else 1
        c = text[p]
        if c == "\\":
            p += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        p += 1
    return -1


def _cook(body: str) -> str:
    """Decode the escapes in a string literal's body to the JS value."""
    if "\\" not in body:
        return body
    s = _ESCAPE_RX.sub(_unescape, body)
    try:
        return s.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeDecodeError:
        return s


def _unescape(m) -> str:
    e = m.group(1)
    if e in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[e]
    if e[0] == "x":
        return chr(int(e[1:], 16))
    if e[0] == "u" and len(e) > 1:
        cp = int(e[2:-1] if e[1] == "{" else e[1:], 16)
        return chr(cp) if cp <= 0x10FFFF else "\ufffd"
    return e


def _js_number(s: str):
    t = s.replace("_", "")
    if t.endswith("n"):
        t = t[:-1]
    try:
        if t[:2].lower() in ("0x", "0o", "0b"):
            return int(t, 0)
        if t.isdigit():
            return int(t)
        return float(t)
    except ValueError:
        return None


def _match_brackets(kinds) -> array:
    """match[i] is the index of the bracket paired with kinds[i], or -1."""
    match = array("l", [-1]) * len(kinds)
    stack = []
    for idx, kind in enumerate(kinds):
        if kind in _OPENERS:
            stack.append(idx)
        elif kind in _CLOSERS:
            if stack and kinds[stack[-1]] == _CLOSERS[kind]:
                opener = stack.pop()
                match[opener] = idx
                match[idx] = opener
    return match


def _call_sites(kinds, vals, match, ctx, angles=None):
    """(name token, "(" token) for each registerTool call, skipping definitions.
    The "(" is None when TypeScript type arguments hide where the call starts.

    `x.registerTool(...)`, `x?.registerTool?.(...)` and `x["registerTool"](...)`
    are always calls. A bare `registerTool(...) {` is a method definition only
    inside an object literal or class body; anywhere else it is a call
    followed by a block. In TypeScript the same goes for a bare
    `registerTool(tool: Tool)` that starts a member there, since only a
    signature has a typed parameter, and an interface body counts as a class.
    """
    for k in range(len(kinds) - 3):
        kind = kinds[k]
        if kind == "I" and vals[k] == "registerTool":
            p = k + 1
            dotted = k > 0 and kinds[k - 1] in (".", "?.")
        elif (kind in ("S", "T") and vals[k] == "registerTool" and k > 0
              and kinds[k - 1] == "[" and kinds[k + 1] == "]"):
            p = k + 2
            dotted = True
        else:
            continue
        if angles is not None and kinds[p] == "!":
            p += 1
        if kinds[p] == "?.":
            p += 1
        if angles is not None and kinds[p] == "<":
            p = angles.get(p)
            if p is None:
                yield k, None
                continue
        if kinds[p] != "(":
            continue
        if not dotted:
            if k > 0 and kinds[k - 1] == "I" and vals[k - 1] == "function":
                continue
            if k > 1 and kinds[k - 1] == "*" and kinds[k - 2] == "I" and vals[k - 2] == "function":
                continue
            if ctx.get(k) in ("expr", "class"):
                close = match[p]
                if close != -1 and kinds[close + 1] == "{":
                    continue
                if (angles is not None and _starts_member(kinds, vals, k)
                        and _typed_parameter(kinds, match, p)):
                    continue
        yield k, p


def _match_angles(kinds) -> dict:
    """For each "<" that a ">" later closes inside the same brackets, the
    index just past that ">". A "<" can also be less-than, so this is only
    asked about one that opens type arguments, and inside those every "<"
    and ">" pairs up."""
    after = {}
    levels = [("", [])]
    for idx, kind in enumerate(kinds):
        if kind in _OPENERS:
            levels.append((kind, []))
        elif kind in _CLOSERS:
            if len(levels) > 1 and levels[-1][0] == _CLOSERS[kind]:
                levels.pop()
        elif kind == "<":
            levels[-1][1].append(idx)
        elif kind in _ANGLE_CLOSERS:
            opened = levels[-1][1]
            for _ in range(min(_ANGLE_CLOSERS[kind], len(opened))):
                after[opened.pop()] = idx + 1
    return after


def _starts_member(kinds, vals, k) -> bool:
    """Whether token k can start a member of a class, interface or object
    type rather than sit where a value goes."""
    prev = kinds[k - 1] if k > 0 else None
    if prev == "I":
        return vals[k - 1] not in _VALUE_WORDS
    return prev in _MEMBER_STARTS


def _typed_parameter(kinds, match, paren) -> bool:
    """Whether the first parameter in the (...) at `paren` has a type
    annotation, as in `(tool: Tool)`, `(tool?: Tool)` or `({a}: Tool)`."""
    i = paren + 1
    if kinds[i] == "...":
        i += 1
    if kinds[i] == "I":
        i += 1
        if kinds[i] == "?":
            i += 1
    elif kinds[i] in ("{", "[") and match[i] != -1:
        i = match[i] + 1
    else:
        return False
    return kinds[i] == ":"


def _read_call(kinds, vals, match, paren) -> dict:
    i = paren + 1
    if kinds[i] == ")":
        raise _Unreadable("it is called with no argument")
    if kinds[i] != "{":
        raise _Unreadable("its argument is not an object literal")
    if match[i] == -1:
        raise _Unreadable("its object literal never closes")
    return _read_object(kinds, vals, match, i)


def _read_object(kinds, vals, match, i) -> dict:
    """Read the object literal whose "{" is at token i into a dict."""
    root = {}
    stack = [(root, "")]
    i += 1
    where = ""
    while True:
        cur, path = stack[-1]
        if kinds[i] == ("}" if isinstance(cur, dict) else "]"):
            i += 1
            stack.pop()
            if not stack:
                return root
            where = path
        else:
            key = None
            if isinstance(cur, dict):
                key, where, i, is_method = _read_key(kinds, vals, match, i, path)
                if is_method:
                    value, container = _FUNCTION, None
                else:
                    value, container, i = _read_value(kinds, vals, match, i + 1, where)
            elif kinds[i] == ",":
                cur.append(None)
                i += 1
                continue
            else:
                where = f"{path}[{len(cur)}]"
                value, container, i = _read_value(kinds, vals, match, i, where)

            if container is not None:
                if len(stack) >= MAX_NESTING:
                    raise _Unreadable(
                        f"its object literal is nested more than {MAX_NESTING} levels deep")
                if key is None:
                    cur.append(container)
                else:
                    cur[key] = container
                stack.append((container, where))
                continue
            if value is _FUNCTION:
                if key != "execute":
                    raise _Unreadable(f'"{where}" is a function')
            elif key is not None:
                if value is not _UNDEFINED:
                    cur[key] = value
            else:
                cur.append(None if value is _UNDEFINED else value)

        cur, _path = stack[-1]
        if kinds[i] == "I" and vals[i] in ("as", "satisfies"):
            end = _type_end(kinds, match, i + 1, (",", "}", "]"))
            if end is None or end == i + 1:
                raise _Unreadable(f'"{where}" has a type after it that the scanner cannot read')
            i = end
        if kinds[i] == ",":
            i += 1
        elif kinds[i] != ("}" if isinstance(cur, dict) else "]"):
            raise _Unreadable(f'"{where}" is set from a variable or expression, not a literal')


def _read_key(kinds, vals, match, i, path):
    """(key, label, index after it, is_method). The index points at the ":"
    of a plain property, or past the body of a method."""
    label = f'"{path}"' if path else "the tool object"
    kind = kinds[i]
    if kind == "...":
        raise _Unreadable(f"{label} uses a spread (...)")
    if kind == "I" and vals[i] in ("get", "set") and kinds[i + 1] in _KEY_STARTS:
        raise _Unreadable(f"{label} has a getter or setter")
    prefixed = False
    if kind == "I" and vals[i] == "async" and (kinds[i + 1] in _KEY_STARTS or kinds[i + 1] == "*"):
        prefixed = True
        i += 1
        kind = kinds[i]
    if kind == "*":
        prefixed = True
        i += 1
        kind = kinds[i]
    if kind in ("I", "S"):
        key = vals[i]
    elif kind == "N" and vals[i] is not None:
        key = _number_key(vals[i])
    elif kind == "[":
        raise _Unreadable(f"{label} has a computed [key]")
    else:
        raise _Unreadable(f"{label} has syntax this scanner cannot read")
    where = f"{path}.{key}" if path else key
    i += 1
    if kinds[i] == "(" and match[i] != -1:
        body = match[i] + 1
        if kinds[body] == ":":
            body = _body_after_type(kinds, match, body)
        if body is not None and kinds[body] == "{" and match[body] != -1:
            return key, where, match[body] + 1, True
    if not prefixed and kinds[i] == ":":
        return key, where, i, False
    if not prefixed and kind == "I" and kinds[i] in (",", "}"):
        raise _Unreadable(f'"{where}" is shorthand for a variable of the same name')
    raise _Unreadable(f"{label} has syntax this scanner cannot read")


def _number_key(v) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v)


def _read_value(kinds, vals, match, i, where):
    """(scalar value, new container, index after it). Exactly one of the
    first two is meaningful: a "{" or "[" comes back as an empty container
    to fill, anything else as a value."""
    kind = kinds[i]
    if kind == "S":
        return vals[i], None, i + 1
    if kind == "T":
        if vals[i] is None:
            raise _Unreadable(f'"{where}" is a template literal with ${{...}} in it')
        return vals[i], None, i + 1
    if kind == "N" and vals[i] is not None:
        return vals[i], None, i + 1
    if kind in ("-", "+") and kinds[i + 1] == "N" and vals[i + 1] is not None:
        return (-vals[i + 1] if kind == "-" else vals[i + 1]), None, i + 2
    if kind == "{":
        return None, {}, i + 1
    if kind == "[":
        return None, [], i + 1
    if kind == "I" and vals[i] in _LITERAL_WORDS:
        return _LITERAL_WORDS[vals[i]], None, i + 1
    end = _skip_function(kinds, vals, match, i)
    if end is not None:
        return _FUNCTION, None, end
    if kind == "...":
        raise _Unreadable(f'"{where.rpartition("[")[0]}" uses a spread (...)')
    raise _Unreadable(f'"{where}" is set from a variable or expression, not a literal')


def _skip_function(kinds, vals, match, i):
    """If a function or arrow function starts at token i, the index just past
    it, else None."""
    if kinds[i] == "I" and vals[i] == "async":
        nxt = kinds[i + 1]
        if nxt == "(" or (nxt == "I" and (vals[i + 1] == "function" or kinds[i + 2] == "=>")):
            i += 1
    if kinds[i] == "I" and vals[i] == "function":
        i += 1
        if kinds[i] == "*":
            i += 1
        if kinds[i] == "I":
            i += 1
        if kinds[i] != "(" or match[i] == -1:
            return None
        i = match[i] + 1
        if kinds[i] == ":":
            i = _body_after_type(kinds, match, i)
            if i is None:
                return None
        if kinds[i] != "{" or match[i] == -1:
            return None
        return match[i] + 1
    if kinds[i] == "(" and match[i] != -1:
        i = match[i] + 1
        if kinds[i] == ":":
            i = _type_end(kinds, match, i + 1, ("=>",))
            if i is None:
                return None
    elif kinds[i] == "I":
        i += 1
    else:
        return None
    if kinds[i] != "=>":
        return None
    i += 1
    if kinds[i] == "{":
        return match[i] + 1 if match[i] != -1 else None
    while True:
        kind = kinds[i]
        if kind in _OPENERS:
            if match[i] == -1:
                return None
            i = match[i] + 1
        elif kind in _STOPS:
            return None if kind == "E" else i
        else:
            i += 1


def _type_end(kinds, match, i, stops):
    """Index of the first token from i in `stops` that is outside every
    bracket and <...> of a TypeScript type, or None."""
    depth = 0
    while True:
        kind = kinds[i]
        if kind in _OPENERS:
            if match[i] == -1:
                return None
            i = match[i] + 1
            continue
        if depth == 0 and kind in stops:
            return i
        if kind in _CLOSERS or kind in (";", "E"):
            return None
        if kind == "<":
            depth += 1
        elif kind in _ANGLE_CLOSERS:
            depth -= _ANGLE_CLOSERS[kind]
            if depth < 0:
                return None
        i += 1


def _body_after_type(kinds, match, colon):
    """The "{" of a function body after the return type whose ":" is at
    `colon`, or None. The type can itself be an object type, so the body is
    the last {...} before the "," or "}" that ends the property."""
    end = _type_end(kinds, match, colon + 1, (",", "}"))
    if end is None or kinds[end - 1] != "}":
        return None
    body = match[end - 1]
    return body if body > colon + 1 else None


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_HTML_WS_RX = re.compile(r"[\t\n\f\r ]*")
_TAG_NAME_RX = re.compile(r"[^\t\n\f\r />]*")
_ATTR_NAME_RX = re.compile(r"[^\t\n\f\r />][^\t\n\f\r />=]*")
_UNQUOTED_RX = re.compile(r"[^\t\n\f\r >]*")
_COMMENT_CLOSE_RX = re.compile(r"--!?>")
# re.A: a browser lowercases tag names in ASCII only, so must the end-tag search.
_SCRIPT_DATA_RX = re.compile(r"<!--|</script[\t\n\f\r />]", re.I | re.A)
_SCRIPT_ESCAPED_RX = re.compile(r"-->|</script[\t\n\f\r />]|<script[\t\n\f\r />]", re.I | re.A)
_SCRIPT_DOUBLE_RX = re.compile(r"-->|</script[\t\n\f\r />]", re.I | re.A)
_RAW_TEXT_END_RX = {
    name: re.compile(r"</" + name + r"[\t\n\f\r />]", re.I | re.A)
    for name in ("style", "xmp", "iframe", "noembed", "noframes", "noscript", "textarea", "title")}
_CHARREF_RX = re.compile(r"&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)")
# Start tags that end SVG or MathML content and go back to HTML.
_BREAKOUT = frozenset((
    "b big blockquote body br center code dd div dl dt em embed h1 h2 h3 h4 h5 h6 head hr "
    "i img li listing menu meta nobr ol p pre ruby s small span strong strike sub sup "
    "table tt u ul var").split())
_MAX_FOREIGN_DEPTH = 512


class _HtmlWalk:
    """One pass over a page the way a browser's HTML tokenizer makes it.

    sources: (JS text, offset map, is a module) per <script>. unread: page
    offsets of each registerTool( inside an attribute value. values: the
    (start, end) of every attribute value. uncertain: the offset where the
    walk met markup it cannot follow, or the page length.
    """

    def __init__(self, html: str):
        self.html = html
        self.sources = []
        self.unread = []
        self.values = []
        self.uncertain = len(html)
        self.foreign = []  # open SVG/MathML elements: (name, namespace, integration point)
        self.in_select = False
        self.svg_script = None  # [depth, text pieces, start] of an SVG <script> being read
        self._walk()

    def _walk(self):
        html = self.html
        n = len(html)
        pos = 0
        while pos < n:
            lt = html.find("<", pos)
            if lt == -1:
                lt = n
            if lt > pos:
                self._text(pos, lt, True)
            if lt == n:
                break
            if html.startswith("<!--", lt):
                pos = _comment_end(html, lt + 4)
                continue
            c = html[lt + 1:lt + 2]
            if c == "!":
                if self.foreign and html.startswith("[CDATA[", lt + 2):
                    end = html.find("]]>", lt + 9)
                    self._text(lt + 9, n if end == -1 else end, False)
                    pos = n if end == -1 else end + 3
                else:
                    pos = _past(html, ">", lt + 2)
            elif c == "?":
                pos = _past(html, ">", lt + 2)
            elif c == "/":
                c2 = html[lt + 2:lt + 3]
                if c2.isascii() and c2.isalpha():
                    pos = self._tag(lt, lt + 2, True)
                elif c2 == ">":
                    pos = lt + 3
                elif not c2:
                    self._text(lt, n, True)
                    pos = n
                else:
                    pos = _past(html, ">", lt + 2)
            elif c.isascii() and c.isalpha():
                pos = self._tag(lt, lt + 1, False)
            else:
                self._text(lt, lt + 1, True)
                pos = lt + 1
        if self.svg_script is not None:
            self._end_svg_script()

    def _text(self, a: int, b: int, decode: bool):
        script = self.svg_script
        if script is not None and len(self.foreign) == script[0]:
            script[1].append((self.html[a:b], a, decode))

    def _tag(self, lt: int, i: int, end_tag: bool) -> int:
        name, end, attrs, self_closing, closed = _read_tag(self.html, i)
        if not closed:
            return len(self.html)
        self._attributes(attrs)
        if end_tag:
            if self.foreign:
                self._foreign_end(lt, name)
            elif self.in_select and name not in ("option", "optgroup"):
                if name == "select":
                    self.in_select = False
                else:
                    self._bail(lt)
            return end
        if self.foreign:
            if self._foreign_start(name, attrs, self_closing, end):
                return end
            self._bail(lt)
        elif self.in_select:
            if name in ("option", "optgroup", "hr"):
                return end
            self._bail(lt)
        return self._html_start(lt, name, attrs, end, self_closing)

    def _html_start(self, lt, name, attrs, end, self_closing) -> int:
        html = self.html
        if name == "script":
            stop = _script_end(html, end)
            kind = next((v for a, v, _ in attrs if a == "type"), "")
            module = kind.strip("\t\n\f\r ").translate(_ASCII_LOWER) == "module"
            self.sources.append((html[end:stop], _shifted(end), module))
            return stop
        if name in _RAW_TEXT_END_RX:
            m = _RAW_TEXT_END_RX[name].search(html, end)
            return m.start() if m else len(html)
        if name == "plaintext":
            return len(html)
        if name in ("svg", "math"):
            if not self_closing:
                self.foreign = [(name, name, None)]
        elif name == "select":
            self.in_select = True
        elif name == "frameset":
            self._bail(lt)
        return end

    def _foreign_start(self, name, attrs, self_closing, end) -> bool:
        """Push a start tag inside SVG or MathML, or False when a browser
        would hand it to the HTML rules instead."""
        current, ns, point = self.foreign[-1]
        if point == "html" or (point == "text" and name not in ("mglyph", "malignmark")):
            return False
        if ns == "math" and current == "annotation-xml" and name == "svg":
            return False
        if name in _BREAKOUT or (name == "font" and any(
                a in ("color", "face", "size") for a, _v, _o in attrs)):
            return False
        if self_closing:
            return True
        if len(self.foreign) >= _MAX_FOREIGN_DEPTH:
            return False
        is_script = ns == "svg" and name == "script"
        if is_script and self.svg_script is not None:
            return False
        point = None
        if ns == "svg" and name in ("foreignobject", "desc", "title"):
            point = "html"
        elif ns == "math" and name in ("mi", "mo", "mn", "ms", "mtext"):
            point = "text"
        elif ns == "math" and name == "annotation-xml" and any(
                a == "encoding" and v.translate(_ASCII_LOWER) in ("text/html", "application/xhtml+xml")
                for a, v, _o in attrs):
            point = "html"
        self.foreign.append((name, ns, point))
        if is_script:
            self.svg_script = [len(self.foreign), [], end]
        return True

    def _foreign_end(self, lt: int, name: str):
        if name not in ("br", "p"):
            for idx in range(len(self.foreign) - 1, -1, -1):
                if self.foreign[idx][0] == name:
                    del self.foreign[idx:]
                    if self.svg_script is not None and len(self.foreign) < self.svg_script[0]:
                        self._end_svg_script()
                    return
        self._bail(lt)

    def _end_svg_script(self):
        text, where = _joined(self.svg_script[1])
        self.svg_script = None
        self.sources.append((text, where, False))

    def _bail(self, at: int):
        """Stop trusting the walk from `at` on. It keeps going as plain HTML,
        but scan_source() reports every registerTool( after this point it did
        not read as a call."""
        if self.svg_script is not None:
            at = min(at, self.svg_script[2])
            self._end_svg_script()
        self.uncertain = min(self.uncertain, at)
        self.foreign = []
        self.in_select = False

    def _attributes(self, attrs):
        for _name, value, start in attrs:
            if not value:
                continue
            self.values.append((start, start + len(value)))
            if "&" in value:
                text = _html.unescape(value)
                self.unread.extend(start for _m in _CANDIDATE_RX.finditer(text))
            else:
                self.unread.extend(start + m.start() for m in _CANDIDATE_RX.finditer(value))


def _read_tag(html: str, i: int):
    """Tokenize the tag whose name starts at i the way a browser does.

    Returns (lowercase name, index past the tag, [(attribute, value, offset
    of the value)], self-closing, closed). A tag the end of the file cuts
    off is never emitted by a browser, so closed is False and the rest of
    the page is gone with it.
    """
    n = len(html)
    m = _TAG_NAME_RX.match(html, i)
    name = m.group().translate(_ASCII_LOWER)
    p = m.end()
    attrs = []
    while True:
        p = _HTML_WS_RX.match(html, p).end()
        if p >= n:
            return name, n, attrs, False, False
        c = html[p]
        if c == ">":
            return name, p + 1, attrs, False, True
        if c == "/":
            if html.startswith(">", p + 1):
                return name, p + 2, attrs, True, True
            p += 1
            continue
        m = _ATTR_NAME_RX.match(html, p)
        attr = m.group().translate(_ASCII_LOWER)
        p = _HTML_WS_RX.match(html, m.end()).end()
        if not html.startswith("=", p):
            attrs.append((attr, "", p))
            continue
        p = _HTML_WS_RX.match(html, p + 1).end()
        quote = html[p:p + 1]
        if not quote:
            return name, n, attrs, False, False
        if quote in ('"', "'"):
            end = html.find(quote, p + 1)
            if end == -1:
                return name, n, attrs, False, False
            attrs.append((attr, html[p + 1:end], p + 1))
            p = end + 1
        elif quote == ">":
            attrs.append((attr, "", p))
            return name, p + 1, attrs, False, True
        else:
            m = _UNQUOTED_RX.match(html, p)
            attrs.append((attr, m.group(), p))
            p = m.end()


def _comment_end(html: str, p: int) -> int:
    """Index past the comment whose "<!--" ends at p. "<!-->", "<!--->" and
    "--!>" all close a comment too."""
    if html.startswith(">", p):
        return p + 1
    if html.startswith("->", p):
        return p + 2
    m = _COMMENT_CLOSE_RX.search(html, p)
    return len(html) if m is None else m.end()


def _script_end(html: str, i: int) -> int:
    """Where the text of a <script> starting at i ends: at its "</script"
    end tag, or the end of the page.

    Inside "<!--", a "<script>" makes the next "</script>" part of the text
    instead of the end of it, until "-->". Browsers do this so an old page
    that wraps document.write("<script>...</script>") in a comment still works.
    """
    state = 0
    m = None
    while True:
        if state == 0:
            m = _SCRIPT_DATA_RX.search(html, i)
            if m is None:
                return len(html)
            if m.group() != "<!--":
                return m.start()
            state, i = 1, m.start() + 2
        elif state == 1:
            m = _SCRIPT_ESCAPED_RX.search(html, i)
            if m is None:
                return len(html)
            token = m.group()
            if token == "-->":
                state = 0
            elif token[1] == "/":
                return m.start()
            else:
                state = 2
            i = m.end()
        else:
            m = _SCRIPT_DOUBLE_RX.search(html, i)
            if m is None:
                return len(html)
            state = 0 if m.group() == "-->" else 1
            i = m.end()


def _past(html: str, ch: str, i: int) -> int:
    j = html.find(ch, i)
    return len(html) if j == -1 else j + 1


def _joined(pieces):
    """Join the text of an SVG <script> and decode its character references,
    as a browser does. Returns the text and a map from its offsets to the page."""
    parts = []
    at, origin, exact = array("l"), array("l"), bytearray()
    size = 0

    def add(s, src, is_exact):
        nonlocal size
        if s:
            parts.append(s)
            at.append(size)
            origin.append(src)
            exact.append(is_exact)
            size += len(s)

    for raw, src, decode in pieces:
        if not decode or "&" not in raw:
            add(raw, src, 1)
            continue
        last = 0
        for m in _CHARREF_RX.finditer(raw):
            add(raw[last:m.start()], src + last, 1)
            add(_html.unescape(m.group()), src + m.start(), 0)
            last = m.end()
        add(raw[last:], src + last, 1)

    def where(off):
        i = bisect_right(at, off) - 1
        return origin[i] + (off - at[i]) if exact[i] else origin[i]

    return "".join(parts), where


def load(path: Path) -> Manifest:
    """Load a Manifest by scanning JS/HTML source for registerTool(...) calls.

    Mirrors manifest.load()'s contract so nothing downstream (scan_files,
    schema.py's not_scanned handling, the human/JSON/SARIF renderers) needs
    to know which loader produced a given Manifest: this never raises, an
    unreadable or oversized file becomes a parse_error, and a file with no
    readable registerTool call becomes a structure_error - "not scanned",
    never a silent clean pass. Calls it could not read next to ones it could
    are kept in unread_calls.
    """
    m = Manifest(path=path, relpath=str(path), source=True)
    try:
        size = path.stat().st_size
    except OSError as e:
        m.parse_error = f"could not stat file: {e}"
        return m

    m.oversized = size > MAX_FILE_BYTES
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES)
    except OSError as e:
        m.parse_error = f"could not read file: {e}"
        return m

    if m.oversized:
        m.parse_error = (
            f"file is larger than the {MAX_FILE_BYTES}-byte scan limit "
            f"({size} bytes), so it was not scanned")
        return m

    text, decode_error = _decode(raw)
    if decode_error:
        m.parse_error = decode_error
        return m
    m.text = text

    suffix = path.suffix.lower()
    calls = scan_source(text, html=suffix in _HTML_EXTENSIONS,
                        module=True if suffix in _MODULE_EXTENSIONS else None,
                        ts=suffix in _TS_EXTENSIONS, jsx=suffix not in _NO_JSX_EXTENSIONS)
    readable = [c for c in calls if c.tool is not None]
    unread = [c for c in calls if c.tool is None]
    if not calls:
        m.structure_error = "no document.modelContext.registerTool(...) call was found"
        return m
    if not readable:
        m.structure_error = (
            f"found {len(calls)} registerTool(...) call(s) but could not read any "
            f"of them ({describe_unread(unread)})")
        return m
    m.tools = [_normalize_tool(i, c.tool) for i, c in enumerate(readable)]
    for tool, call in zip(m.tools, readable):
        tool.line = call.line
    m.unread_calls = [(c.line, c.problem) for c in unread]
    return m
