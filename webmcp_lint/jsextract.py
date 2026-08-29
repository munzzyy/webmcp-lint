"""Best-effort extraction of WebMCP tool definitions straight out of JS source.

WebMCP has no manifest file in the spec: a page registers each tool at
runtime with a call like:

    document.modelContext.registerTool({
      name: "getWeather",
      description: "...",
      inputSchema: {...},
    });

Most real sites never produce a JSON file at all, so a linter that only
reads JSON has nothing to scan on them. This module closes that gap the only
way that's honest about what it is: it is NOT a JS parser. It is a
bracket-matching scanner that finds each `registerTool(` call, grabs the
balanced object-literal argument that follows, and repairs it with a
handful of tolerant passes (single- and back-quoted strings to double,
unquoted keys quoted, trailing commas dropped) until json.loads accepts it.

Anything dynamic - a spread, a variable standing in for a whole field, a
template literal with a `${...}` interpolation, a description built by
concatenation - is out of reach. That call site is silently skipped rather
than half-parsed into something wrong. See README's "What it does not do"
for what this means in practice: point it at readable, mostly-literal
source for real coverage, and treat a clean result on minified or
heavily-dynamic JS as "nothing found", not "nothing wrong".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .manifest import MAX_FILE_BYTES, Manifest, _decode, _normalize_tool

# Extensions scan_files() routes through this module instead of manifest.py.
JS_EXTENSIONS = (".js", ".mjs", ".html", ".htm")

_CALL_RX = re.compile(r"registerTool\s*\(")

_BLOCK_COMMENT_RX = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RX = re.compile(r"//[^\n]*")
_TRAILING_COMMA_RX = re.compile(r",(\s*[}\]])")
# key: ... -> "key": ... . Only fires right after "{" or "," so it never
# touches a bare word inside a string or a value position.
_UNQUOTED_KEY_RX = re.compile(r'([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)(\s*:)')


def extract_tools(text: str) -> list:
    """Return the tool dicts found via registerTool({...}) calls in `text`.

    Best effort: a call whose argument isn't an object literal, or whose
    literal can't be coaxed into valid JSON, is skipped rather than raising
    or reporting an error - a scanner this simple is expected to miss
    dynamic call sites.
    """
    tools = []
    for m in _CALL_RX.finditer(text):
        obj_text = _read_balanced_object(text, m.end())
        if obj_text is None:
            continue
        try:
            data = json.loads(_js_object_to_json(obj_text))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            tools.append(data)
    return tools


def _read_balanced_object(text: str, pos: int):
    """Starting at `pos` (just past the call's opening paren), skip leading
    whitespace and return the text from "{" through its matching "}", or
    None if the argument isn't an object literal (a bare variable, a spread,
    a function call) or the braces never close before the file ends.

    Tracks whether each character is inside a string so a brace or quote
    quoted inside "description": "a } here" doesn't unbalance the count.
    """
    n = len(text)
    i = pos
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n or text[i] != "{":
        return None
    depth = 0
    in_str = None
    escaped = False
    j = i
    while j < n:
        c = text[j]
        if in_str:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == in_str:
                in_str = None
        elif c in "\"'`":
            in_str = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return None


def _js_object_to_json(obj_text: str) -> str:
    """Repair a JS object literal into text json.loads can accept.

    Order matters: comments are stripped before string normalization so a
    "//" or "/*" that only happens to sit inside a string isn't mistaken for
    one (normalization runs a real string-aware scan and would otherwise
    have protected it); unquoted keys are quoted before the trailing-comma
    pass so a key immediately before a closing brace doesn't get walked in
    the same regex pass twice.
    """
    text = _BLOCK_COMMENT_RX.sub("", obj_text)
    text = _LINE_COMMENT_RX.sub("", text)
    text = _normalize_strings(text)
    text = _UNQUOTED_KEY_RX.sub(lambda m: f'{m.group(1)}"{m.group(2)}"{m.group(3)}', text)
    text = _TRAILING_COMMA_RX.sub(r"\1", text)
    return text


def _normalize_strings(text: str) -> str:
    """Rewrite every single- or back-quoted string literal as a double-quoted
    JSON string, leaving already-double-quoted strings untouched.

    A template literal with a `${...}` interpolation carries content this
    scanner cannot evaluate, so its interpolation markers are kept literally
    in the output rather than papered over - that reliably fails the
    json.loads call in extract_tools(), which is what "skip this call site"
    is supposed to look like, instead of silently inventing a value.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c not in "\"'`":
            out.append(c)
            i += 1
            continue
        quote = c
        j = i + 1
        body = []
        has_interp = False
        while j < n:
            cj = text[j]
            if cj == "\\" and j + 1 < n:
                body.append(text[j:j + 2])
                j += 2
                continue
            if quote == "`" and cj == "$" and j + 1 < n and text[j + 1] == "{":
                has_interp = True
            if cj == quote:
                j += 1
                break
            body.append(cj)
            j += 1
        if quote == "`" and has_interp:
            # The real value only exists at runtime. Emitting an unquoted
            # token guarantees json.loads rejects the surrounding object, so
            # extract_tools() skips this call site instead of reporting a
            # description that was never actually there.
            out.append("\x00DYNAMIC\x00")
        elif quote == '"':
            out.append('"' + "".join(body) + '"')
        else:
            # Un-escape the delimiter this string used (JS lets you escape a
            # quote you don't need to once the delimiter changes), then
            # escape any literal double quote so the result is valid JSON.
            raw = "".join(body).replace("\\" + quote, quote).replace('"', '\\"')
            out.append('"' + raw + '"')
        i = j
    return "".join(out)


def load(path: Path) -> Manifest:
    """Load a Manifest by scanning JS/HTML source for registerTool(...) calls.

    Mirrors manifest.load()'s contract so nothing downstream (scan_files,
    schema.py's not_scanned handling, the human/JSON/SARIF renderers) needs
    to know which loader produced a given Manifest: this never raises, an
    unreadable or oversized file becomes a parse_error, and a file with no
    registerTool call at all becomes a structure_error - "not scanned",
    never a silent clean pass.
    """
    m = Manifest(path=path, relpath=str(path))
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

    raw_tools = extract_tools(text)
    if not raw_tools:
        m.structure_error = (
            "no document.modelContext.registerTool(...) call with a literal "
            "object argument was found. This is a best-effort source scan, "
            "not a JS parser - a tool built from a variable, a spread, or a "
            "template literal with interpolation is invisible to it (see "
            'README\'s "What it does not do")')
        return m
    m.tools = [_normalize_tool(i, t) for i, t in enumerate(raw_tools)]
    return m
