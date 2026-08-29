"""Command-line interface for webmcp-lint."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .discovery import resolve_targets
from .finding import Severity
from .report import render_human, render_json, render_sarif
from .rules import RULE_IDS
from .scanner import scan_files

_NO_THRESHOLD = ("none", "off", "never")


class UsageError(Exception):
    """A problem with the command line, not with the manifest. Exits 2."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webmcp-lint",
        description="Security and spec-correctness linter for WebMCP tool manifests.",
    )
    p.add_argument(
        "target",
        help="a manifest file, a directory (looks for mcp.json / webmcp.json / "
             ".well-known/mcp.json inside it), or a glob pattern",
    )
    p.add_argument(
        "--recursive", "-r", action="store_true",
        help="when the target is a directory, also look inside its subdirectories "
             "(skips node_modules, .git, dist, build, venv, .venv, __pycache__, .tox)",
    )
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 (for GitHub code scanning)")
    # --quiet belongs in the group. It used to lose silently to --json and
    # --sarif, and a flag that does nothing without saying so is how people
    # stop trusting the rest of them.
    out.add_argument("--quiet", action="store_true", help="only print the summary line and grade")
    p.add_argument(
        "--fail-on", default="high", metavar="SEVERITY",
        help="exit non-zero if any finding is at or above this severity "
             "(critical|high|medium|low|info|none; default: high)",
    )
    p.add_argument(
        "--ignore", action="append", default=[], metavar="RULE",
        help="suppress a rule everywhere, grade and exit code included "
             "(repeatable, or comma-separated: --ignore WML-002,WML-004)",
    )
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--version", action="version", version=f"webmcp-lint {__version__}")
    return p


def _fail_threshold(value: str):
    value = value.strip().lower()
    if value in _NO_THRESHOLD:
        return None
    try:
        return Severity.parse(value)
    except ValueError:
        raise UsageError(
            f"invalid --fail-on value {value!r}; expected one of "
            "critical, high, medium, low, info, none")


def _ignored_rules(values) -> set:
    """Rule ids to suppress, validated.

    A typo is rejected rather than quietly suppressing nothing. Someone who
    thinks they turned a rule off and did not is worse off than someone who
    gets told they misspelled it.
    """
    known = {r.upper() for r in RULE_IDS}
    wanted = set()
    for value in values:
        for part in value.split(","):
            part = part.strip().upper()
            if part:
                wanted.add(part)
    unknown = sorted(wanted - known)
    if unknown:
        raise UsageError(
            "unknown rule id(s) passed to --ignore: " + ", ".join(unknown)
            + "; known rules are " + ", ".join(sorted(known)))
    return wanted


def _configure_streams() -> None:
    """Keep a non-ASCII report from killing the process on Windows.

    With output redirected to a file or a pipe, Python encodes stdout with the
    locale encoding, which is cp1252 on a default US Windows install. A single
    U+202E then raises UnicodeEncodeError and the run dies with a truncated
    report. U+202E is the right-to-left override WML-008 exists to find, so the
    tool was dying on exactly the manifests it is built to catch, and the
    bundled composite action redirects on every run.

    backslashreplace rather than replace: a security report should keep the
    offending codepoint legible as \\u202e, not flatten it to a question mark.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="backslashreplace")
        except (ValueError, OSError):
            pass


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _configure_streams()

    try:
        threshold = _fail_threshold(args.fail_on)
        ignore = _ignored_rules(args.ignore)
    except UsageError as e:
        print(f"webmcp-lint: {e}", file=sys.stderr)
        return 2

    targets = resolve_targets(args.target, recursive=args.recursive)
    if not targets:
        print(f"webmcp-lint: no manifest file(s) matched {args.target!r}", file=sys.stderr)
        return 2

    result = scan_files(targets, root=args.target, ignore=ignore)

    color = not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    if args.json:
        print(render_json(result))
    elif args.sarif:
        print(render_sarif(result))
    elif args.quiet:
        print(f"{result.grade} ({result.grade_score}/100) - "
              f"{sum(result.counts().values())} finding(s), "
              f"{result.tools} tool(s) in {result.manifests} manifest(s)")
    else:
        print(render_human(result, color=color))

    if threshold is not None:
        worst = max((f.severity for f in result.findings), default=None)
        if worst is not None and worst >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
