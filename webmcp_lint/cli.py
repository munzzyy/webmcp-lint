"""Command-line interface for webmcp-lint."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .discovery import resolve_targets
from .finding import Severity
from .report import render_human, render_json, render_sarif
from .scanner import scan_files


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
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 (for GitHub code scanning)")
    p.add_argument(
        "--fail-on", default="high", metavar="SEVERITY",
        help="exit non-zero if any finding is at or above this severity "
             "(critical|high|medium|low|info|none; default: high)",
    )
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--quiet", action="store_true", help="only print the summary line and grade")
    p.add_argument("--version", action="version", version=f"webmcp-lint {__version__}")
    return p


def _fail_threshold(value: str):
    value = value.strip().lower()
    if value in ("none", "off", "never"):
        return None
    try:
        return Severity.parse(value)
    except ValueError:
        raise SystemExit(f"webmcp-lint: invalid --fail-on value {value!r}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    threshold = _fail_threshold(args.fail_on)

    targets = resolve_targets(args.target)
    if not targets:
        print(f"webmcp-lint: no manifest file(s) matched {args.target!r}", file=sys.stderr)
        return 2

    result = scan_files(targets, root=args.target)

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
