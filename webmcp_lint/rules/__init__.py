"""Rule registry.

Each rule module exposes `check(manifest) -> list[Finding]` plus `RULE_ID`,
`TITLE` and `SUMMARY`. The last two feed the SARIF rule metadata, so the
GitHub Security tab shows what a rule means instead of a bare id.
"""

from __future__ import annotations

from . import (
    aggregate,
    budget,
    deprecated_api,
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
RULE_MODULES = (
    schema,
    hygiene,
    readonly,
    untrusted_content,
    injection,
    risky_params,
    exec_capability,
    unicode_smuggling,
    budget,
    aggregate,
    deprecated_api,
)

ALL_RULES = [m.check for m in RULE_MODULES]
RULE_IDS = tuple(m.RULE_ID for m in RULE_MODULES)
RULE_META = {m.RULE_ID: (m.TITLE, m.SUMMARY) for m in RULE_MODULES}


def run_all(manifest) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(manifest))
    return findings
