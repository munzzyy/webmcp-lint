"""Catch injection payloads that no single tool carries.

Every other rule here reads one tool at a time, and that is exactly the gap
recent research targets. ShareLock (arXiv 2606.27027, June 2026) splits an
instruction into shares spread across the descriptions of several
innocuous-looking tools; each fragment passes per-tool inspection on its own
and only reconstitutes once the agent has them all in context. The same paper
reports over 90% success against description-based detection. Payload
splitting and nested encoding both show up in Unit 42's in-the-wild reporting
too.

So this rule does the two passes a per-tool scanner structurally cannot:

1. Join the manifest's text in registration order, which is the order the
   agent receives it in, and re-run the WML-003 patterns over the result.
   Descriptions are joined with descriptions and names with names, as well as
   everything together, because a payload split across two descriptions has
   the intervening tool names in the way otherwise. Only a pattern that did
   not already fire on a single field is reported, so this never duplicates a
   WML-003 finding.
2. Decode base64, hex, and percent-encoded blobs found in any of that text and
   re-run the patterns over what comes out.

The join is a single space and nothing else. Folding keeps genuine sentence
boundaries as a wall the phrase patterns cannot cross, so two ordinary
descriptions that each end in a full stop cannot be welded into a false hit;
a fragment that stops mid-sentence, which is what a split payload looks like,
still joins up.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

from ..finding import Category, Severity
from ._schema_walk import tool_text_fields
from ._util import mk
from .injection import PATTERNS, fold_for_matching

RULE_ID = "WML-010"
TITLE = "Injection payload split across tools or hidden behind an encoding"
SUMMARY = (
    "Prompt-injection phrasing that only appears once every tool's text is "
    "joined in registration order, or once a base64, hex, or percent-encoded "
    "blob in that text is decoded."
)

# Long enough that ordinary prose does not reach it by accident.
_B64 = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
# Enough escapes that a stray "%2" in prose cannot reach it.
_PCT_MIN = 4

_FIX = (
    "Split payloads and encoded blobs have no place in a tool definition. "
    "Remove the directive, and describe the capability in plain text a "
    "reviewer can read as written."
)


def check(manifest) -> list:
    fields = []  # (tool, label, text)
    for tool in manifest.tools:
        for label, text in tool_text_fields(tool):
            fields.append((tool, label, text))
    if not fields:
        return []

    already = set()
    for _tool, _label, text in fields:
        folded = fold_for_matching(text)
        for i, (rx, _t, _d) in enumerate(PATTERNS):
            if rx.search(folded):
                already.add(i)

    findings = []
    findings.extend(_aggregate(manifest, fields, already))
    findings.extend(_encoded(manifest, fields))
    return findings


def _groups(fields) -> list:
    """(what was joined, joined text) for each pass.

    Same-kind fields are joined together as well as everything in order. A
    directive split across two descriptions has the next tool's name sitting
    between the halves in a naive end-to-end join, which is enough to hide it.
    """
    descriptions = [t for _tool, label, t in fields if label == "description"]
    names = [t for _tool, label, t in fields if label == "name"]
    titles = [t for _tool, label, t in fields if label == "title"]
    schema_text = [t for _tool, label, t in fields if "." in label]
    everything = [t for _tool, _label, t in fields]
    candidates = (
        ("the tool descriptions", descriptions),
        ("the tool names", names),
        ("the tool titles", titles),
        ("the parameter descriptions", schema_text),
        ("every field in the manifest", everything),
    )
    return [(what, " ".join(texts)) for what, texts in candidates if len(texts) > 1]


def _aggregate(manifest, fields, already) -> list:
    findings = []
    reported = set(already)
    for what, joined in _groups(fields):
        folded = fold_for_matching(joined)
        for i, (rx, title, detail) in enumerate(PATTERNS):
            if i in reported or not rx.search(folded):
                continue
            reported.add(i)
            findings.append(mk(
                RULE_ID, Category.INJECTION, Severity.HIGH, manifest.relpath,
                f"{title}, assembled across tools",
                f"No single field carries it, but {what} read end to end do: "
                f"{detail} Splitting a directive across several innocuous-looking "
                "tool descriptions is a published way to defeat per-tool scanning, "
                "and the agent sees the whole set at once.",
                _FIX,
            ))
    return findings


def _encoded(manifest, fields) -> list:
    findings = []
    seen = set()
    for tool, label, text in fields:
        plain = fold_for_matching(text)
        # Percent-decoding rewrites the whole field, so a directive that was
        # already readable in the plaintext would otherwise be reported twice,
        # once by WML-003 and once here.
        plain_hits = {i for i, (rx, _t, _d) in enumerate(PATTERNS) if rx.search(plain)}
        for encoding, decoded in _decode_blobs(text):
            folded = fold_for_matching(decoded)
            for i, (rx, title, detail) in enumerate(PATTERNS):
                if i in plain_hits or not rx.search(folded):
                    continue
                key = (tool.index, label, i)
                if key in seen:
                    continue
                seen.add(key)
                where = f'"{tool.name or f"tool #{tool.index}"}" {label}'
                findings.append(mk(
                    RULE_ID, Category.INJECTION, Severity.HIGH, manifest.relpath,
                    f"{title}, hidden behind {encoding} encoding",
                    f"{where} carries a {encoding} blob that decodes to a directive "
                    f"aimed at the agent: {detail} Reviewers see the blob; an agent "
                    "asked to decode or forward it sees the instruction.",
                    _FIX,
                    tool=tool.name, tool_index=tool.index,
                ))
    return findings


def _decode_blobs(text: str):
    """Yield (encoding_name, decoded_text) for blobs that decode to text.

    Anything that does not come back as printable text is dropped, which is
    what keeps an ordinary long identifier from being read as base64.
    """
    for match in _B64.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _as_text(raw)
        if decoded:
            yield "base64", decoded

    for match in _HEX.finditer(text):
        try:
            raw = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        decoded = _as_text(raw)
        if decoded:
            yield "hex", decoded

    if len(_PCT.findall(text)) >= _PCT_MIN:
        decoded = unquote(text)
        if decoded != text:
            yield "percent", decoded


def _as_text(raw: bytes) -> str:
    if len(raw) < 8:
        return ""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\t\n\r")
    if printable < len(decoded) * 0.9:
        return ""
    return decoded
