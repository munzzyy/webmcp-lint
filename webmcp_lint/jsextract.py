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

In an .html file only the contents of <script> elements are read, so prose
on the page and anything inside an HTML comment is ignored.
"""

from __future__ import annotations

import re
from array import array
from dataclasses import dataclass
from pathlib import Path

from .manifest import MAX_FILE_BYTES, Manifest, _decode, _normalize_tool

# Extensions scan_files() routes through this module instead of manifest.py.
JS_EXTENSIONS = (".js", ".mjs", ".html", ".htm")
_HTML_EXTENSIONS = (".html", ".htm")

_HTML_MARK_RX = re.compile(r"<!--|<script\b", re.IGNORECASE)
_SCRIPT_CLOSE_RX = re.compile(r"</script", re.IGNORECASE)
_WS_RX = re.compile(
    r"[ \t\n\r\f\v\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+")
_LINE_BREAKS = ("\n", "\r", "\u2028", "\u2029")
_REST_OF_LINE_RX = re.compile(r"[^\n\r\u2028\u2029]*")
_STRING_STOP_RX = {'"': re.compile(r'["\\\n\r]'), "'": re.compile(r"['\\\n\r]")}
_TEMPLATE_STOP_RX = re.compile(r"[`\\]|\$\{")
_IDENT_RX = re.compile(r"(?:[^\W\d]|\$)(?:\w|\$|\u200c|\u200d)*")
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

# After one of these a "/" starts a regex literal; after anything else it divides.
_REGEX_AFTER_WORDS = frozenset((
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await"))
_NO_REGEX_AFTER = frozenset((")", "]", "++", "--", "S", "T", "N", "R", "X"))

_IN_TEMPLATE = "template"
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


@dataclass
class CallSite:
    line: int  # 1-based line of the registerTool( call
    tool: object = None  # the tool dict, or None when the call could not be read
    problem: str = ""  # why it could not be read


class _Unreadable(Exception):
    pass


def scan_source(text: str, html: bool = False) -> list:
    """Every registerTool(...) call site in `text`, readable or not, in order."""
    blocks = _script_blocks(text) if html else [(text, 1)]
    calls = []
    for block, first_line in blocks:
        calls.extend(_scan_js(block, first_line))
    return calls


def extract_tools(text: str, html: bool = False) -> list:
    """The tool dicts from every registerTool({...}) call that could be read."""
    return [c.tool for c in scan_source(text, html) if c.tool is not None]


def describe_unread(calls) -> str:
    """'line 3: why; line 9: why', for (line, problem) pairs or CallSites."""
    pairs = [(c.line, c.problem) if isinstance(c, CallSite) else c for c in calls]
    shown = "; ".join(f"line {line}: {problem}" for line, problem in pairs[:_LIST_LIMIT])
    if len(pairs) > _LIST_LIMIT:
        shown += f"; and {len(pairs) - _LIST_LIMIT} more"
    return shown


def _script_blocks(html: str) -> list:
    """(script text, line it starts on) for each <script> element."""
    blocks = []
    pos = 0
    line, counted = 1, 0
    while True:
        m = _HTML_MARK_RX.search(html, pos)
        if m is None:
            break
        if m.group() == "<!--":
            end = html.find("-->", m.end())
            if end == -1:
                break
            pos = end + 3
            continue
        gt = html.find(">", m.end())
        if gt == -1:
            break
        body = gt + 1
        close = _SCRIPT_CLOSE_RX.search(html, body)
        end = close.start() if close else len(html)
        line += html.count("\n", counted, body)
        counted = body
        blocks.append((html[body:end], line))
        if close is None:
            break
        pos = close.end()
    return blocks


def _scan_js(text: str, first_line: int) -> list:
    kinds, vals, starts = _tokenize(text)
    kinds.extend(("E", "E", "E"))
    vals.extend((None, None, None))
    match = _match_brackets(kinds)
    out = []
    pos, line = 0, first_line
    for k in _call_sites(kinds, vals, match):
        line += text.count("\n", pos, starts[k])
        pos = starts[k]
        try:
            out.append(CallSite(line, _read_call(kinds, vals, match, k)))
        except _Unreadable as e:
            out.append(CallSite(line, None, str(e)))
    return out


def _tokenize(text: str):
    """Split JS source into tokens in one linear pass.

    Returns parallel lists: kinds, values, start offsets. A punctuator's kind
    is its own text. Other kinds: "I" identifier, "S" string, "T" template
    literal (value None when it has a ${...}), "N" number, "R" regex, "X"
    anything unrecognized. Tokens inside a ${...} substitution are lexed but
    not emitted; the whole template comes out as one "T" token.
    """
    kinds, vals, starts = [], [], array("l")
    n = len(text)
    i = 0
    prev = None
    prev_val = None
    line_has_code = False
    modes = []
    template_start = -1
    regex_memo = [None]

    while i < n:
        if modes and modes[-1] is _IN_TEMPLATE:
            i, stop = _template_stop(text, i)
            if stop == "`":
                modes.pop()
                prev, prev_val = "T", None
                if not modes:
                    kinds.append("T")
                    vals.append(None)
                    starts.append(template_start)
            elif stop == "${":
                modes.append([0])
                prev, prev_val = "(", None
            continue

        c = text[i]
        start = i
        ws = _WS_RX.match(text, i)
        if ws:
            i = ws.end()
            if any(b in ws.group() for b in _LINE_BREAKS):
                line_has_code = False
            continue
        nxt = text[i + 1:i + 2]
        if c == "/" and nxt == "/":
            i = _REST_OF_LINE_RX.match(text, i).end()
            continue
        if c == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            if any(b in text[i:end] for b in _LINE_BREAKS):
                line_has_code = False
            i = end
            continue
        if (c == "<" and text.startswith("<!--", i)) or (
                c == "-" and not line_has_code and text.startswith("-->", i)):
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
                if not modes:
                    template_start = i
                modes.append(_IN_TEMPLATE)
                if stop == "${":
                    modes.append([0])
                    prev, prev_val = "(", None
                i = end
                continue
        elif "0" <= c <= "9" or (c == "." and "0" <= nxt <= "9"):
            m = _NUMBER_RX.match(text, i)
            kind, val, i = "N", _js_number(m.group()), m.end()
        elif c == "/":
            end = -1
            if _regex_allowed(prev, prev_val):
                end = _scan_regex(text, i, regex_memo)
            if end != -1:
                kind, val, i = "R", None, end
            else:
                m = _DIVIDE_RX.match(text, i)
                kind, val, i = m.group(), None, m.end()
        else:
            m = _IDENT_RX.match(text, i)
            if m:
                kind, val, i = "I", m.group(), m.end()
            else:
                m = _PUNCT_RX.match(text, i)
                if m:
                    kind, val, i = m.group(), None, m.end()
                else:
                    kind, val, i = "X", None, i + 1

        line_has_code = True
        if modes:
            depth = modes[-1]
            if kind == "{":
                depth[0] += 1
            elif kind == "}":
                if depth[0] == 0:
                    modes.pop()
                    continue
                depth[0] -= 1
        else:
            kinds.append(kind)
            vals.append(val)
            starts.append(start)
        prev, prev_val = kind, val

    if modes:
        kinds.append("X")
        vals.append(None)
        starts.append(template_start)
    return kinds, vals, starts


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


def _regex_allowed(prev, prev_val) -> bool:
    if prev is None:
        return True
    if prev == "I":
        return prev_val in _REGEX_AFTER_WORDS
    return prev not in _NO_REGEX_AFTER


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


def _call_sites(kinds, vals, match):
    """Token indexes of `registerTool` where it is called, not defined."""
    for k in range(len(kinds) - 1):
        if kinds[k] != "I" or vals[k] != "registerTool" or kinds[k + 1] != "(":
            continue
        if k > 0 and kinds[k - 1] == "I" and vals[k - 1] == "function":
            continue
        close = match[k + 1]
        if close != -1 and kinds[close + 1] == "{":
            continue
        yield k


def _read_call(kinds, vals, match, k) -> dict:
    i = k + 2
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
        if kinds[body] == "{" and match[body] != -1:
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
        if kinds[i] != "{" or match[i] == -1:
            return None
        return match[i] + 1
    if kinds[i] == "(" and match[i] != -1:
        i = match[i] + 1
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

    calls = scan_source(text, html=path.suffix.lower() in _HTML_EXTENSIONS)
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
