"""Rule registry. Each rule module exposes `check(manifest) -> list[Finding]`."""

from __future__ import annotations

from . import (
    exec_capability,
    hygiene,
    injection,
    readonly,
    risky_params,
    schema,
    unicode_smuggling,
    untrusted_content,
)

# schema and hygiene run first: they report the structural problems that
# would otherwise make every other rule silently see zero tools.
ALL_RULES = [
    schema.check,
    hygiene.check,
    readonly.check,
    untrusted_content.check,
    injection.check,
    risky_params.check,
    exec_capability.check,
    unicode_smuggling.check,
]


def run_all(manifest) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(manifest))
    return findings
