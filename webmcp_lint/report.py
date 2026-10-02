"""Render a ScanResult as human text, JSON, or SARIF."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import PurePath

from . import __version__
from .finding import SECURITY_CATEGORIES, ScanResult, Severity
from .rules import RULE_META
from .rules.unicode_smuggling import is_hidden

DOCS_URL = "https://github.com/munzzyy/webmcp-lint/blob/main/docs/rules.md"

_COLOR = {
    Severity.CRITICAL: "\033[1;37;41m",  # white on red
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_GRADE_COLOR = {"A": "\033[32m", "B": "\033[32m", "C": "\033[33m",
                "D": "\033[33m", "F": "\033[1;31m"}


def sanitize(s: str) -> str:
    """Make untrusted manifest text safe to print to a terminal.

    Everything in a finding except webmcp-lint's own wording comes from the
    manifest, and the manifest is the thing under suspicion. A tool name
    holding an escape sequence can erase the lines already printed and repaint
    a green "no findings" in their place, and SECURITY.md calls that out as a
    vulnerability in this tool. So every C0 control character, DEL, and C1
    control gets rendered visibly instead of executed. Newlines and tabs go
    too: a report line is one line, and a description that spans several would
    break the layout the reader is scanning.

    Bidi controls, tag characters and zero-width characters are escaped as
    well. A tool name carrying U+202E would otherwise reorder the very report
    line that flags it, which is the Trojan Source trick WML-008 looks for.
    """
    out = []
    for ch in s:
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            out.append(f"\\x{cp:02x}")
        elif is_hidden(cp):
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
        else:
            out.append(ch)
    return "".join(out)


def render_human(result: ScanResult, color: bool = True) -> str:
    def c(code, s):
        return f"{code}{s}{_RESET}" if color else s

    lines = []
    counts = result.counts()
    total = sum(counts.values())
    unread = sum(1 for f in result.findings if f.not_scanned)

    lines.append("")
    lines.append(f"  webmcp-lint  {sanitize(result.root)}")
    lines.append(f"  {result.manifests} manifest(s), {result.tools} tool(s) scanned")
    if unread:
        lines.append(c("\033[1;31m",
                       f"  {unread} manifest(s) could not be read, so nothing in them was checked"))
    lines.append("")

    if not result.findings:
        lines.append(c("\033[32m", "  No findings. Nothing suspicious surfaced."))
    for f in result.findings:
        tag = c(_COLOR[f.severity], f" {f.severity.label.upper():^8} ")
        tool = sanitize(f.tool)
        loc = sanitize(f.file) + (f'  tool "{tool}"' if f.tool else "")
        lines.append(f"  {tag} {sanitize(f.title)}  [{f.rule_id} - {f.category}]")
        lines.append(f"           {loc}")
        lines.append(f"           {sanitize(f.detail)}")
        if f.remediation:
            lines.append(c("\033[90m", f"           fix: {sanitize(f.remediation)}"))
        lines.append("")

    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if counts[sev]:
            parts.append(c(_COLOR[sev], f"{counts[sev]} {sev.label}"))
    summary = "  " + (", ".join(parts) if parts else "0 findings")
    lines.append(summary + f"   ({total} total)")

    gc = _GRADE_COLOR.get(result.grade, "")
    lines.append("")
    lines.append(f"  Grade: {c(gc, result.grade)}  ({result.grade_score}/100)")
    lines.append("")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": "webmcp-lint",
        "version": __version__,
        "root": result.root,
        "manifests": result.manifests,
        "tools": result.tools,
        "grade": result.grade,
        "grade_score": result.grade_score,
        "counts": {s.label: result.counts()[s] for s in Severity},
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category.value,
                "severity": f.severity.label,
                "title": f.title,
                "detail": f.detail,
                "file": f.file,
                "tool": f.tool,
                "tool_index": f.tool_index,
                "remediation": f.remediation,
                "not_scanned": f.not_scanned,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def sarif_uri(path: str) -> str:
    """A SARIF artifactLocation.uri is a URI reference, not an OS path.

    On Windows f.file is `tests\\corpus\\x.json`; backslashes are not path
    separators in a URI, so the Security tab either mislocates the finding or
    drops it. An absolute runner path matches nothing in the repo either, so
    relativize against the working directory where that is possible.
    """
    if not path:
        return "unknown"
    p = PurePath(path)
    try:
        p = p.relative_to(PurePath(os.getcwd()))
    except ValueError:
        pass
    return p.as_posix().replace("\\", "/")


def _fingerprint(f, uri: str) -> str:
    """Stable per-finding id so GitHub can match an alert across runs instead
    of reopening one the user already dismissed."""
    raw = "|".join((f.rule_id, uri, f.tool, f.title))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _sarif_rules(findings) -> list:
    """One descriptor per rule that fired. Code scanning ranks a security
    alert by the security-severity and "security" tag on its rule. A rule
    that fired at several severities gets the highest one seen in this run.
    Hygiene and size-budget rules get neither; they are not security findings."""
    rules = []
    for rid in sorted({f.rule_id for f in findings}):
        title, summary = RULE_META.get(rid, (rid, ""))
        rule = {
            "id": rid,
            "name": title,
            "shortDescription": {"text": title},
            "fullDescription": {"text": summary or title},
            "helpUri": f"{DOCS_URL}#{rid.lower()}",
        }
        hits = [f for f in findings if f.rule_id == rid and f.category in SECURITY_CATEGORIES]
        if hits:
            rule["properties"] = {
                "tags": ["security"],
                "security-severity": max((_sec_severity(f.severity) for f in hits), key=float),
            }
        rules.append(rule)
    return rules


def render_sarif(result: ScanResult) -> str:
    rules = _sarif_rules(result.findings)
    sarif_results = []
    for f in result.findings:
        message = f"{f.title}: {f.detail}"
        uri = sarif_uri(f.file)
        location = {"uri": uri}
        if not PurePath(uri).is_absolute():
            location["uriBaseId"] = "%SRCROOT%"
        physical = {"artifactLocation": location}
        if f.line:
            physical["region"] = {"startLine": f.line}
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "partialFingerprints": {"webmcpLintFinding/v1": _fingerprint(f, uri)},
            "properties": {
                "security-severity": _sec_severity(f.severity),
                "category": f.category.value,
                "tool": f.tool,
            },
            "locations": [{"physicalLocation": physical}],
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "webmcp-lint",
                "informationUri": "https://github.com/munzzyy/webmcp-lint",
                "version": __version__,
                "rules": rules,
            }},
            "results": sarif_results,
        }],
    }
    return json.dumps(doc, indent=2)


def _sec_severity(sev: Severity) -> str:
    # GitHub code-scanning numeric band (0.0-10.0).
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[sev]
