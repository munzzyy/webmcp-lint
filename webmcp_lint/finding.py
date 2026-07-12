"""Core types: severities, categories, findings, and the scan result."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered so comparisons and sorting work (higher = worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {name!r}")


class Category(str, enum.Enum):
    READONLY = "read-only-hint"
    UNTRUSTED = "untrusted-content"
    INJECTION = "prompt-injection"
    RISKY_PARAM = "risky-parameter"
    EXEC = "arbitrary-execution"
    SCHEMA = "schema"
    HYGIENE = "hygiene"
    UNICODE = "hidden-unicode"

    def __str__(self) -> str:  # nicer output in reports
        return self.value


# Categories that count toward the security grade. HYGIENE is manifest
# housekeeping (duplicate/missing names, empty tool lists), not a security hole.
SECURITY_CATEGORIES = frozenset(c for c in Category if c is not Category.HYGIENE)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    detail: str
    file: str  # manifest path as given on the command line
    tool: str = ""  # tool name, or "" if the finding is manifest-level
    tool_index: int = -1  # position in the tools array, -1 if not tool-specific
    remediation: str = ""

    def sort_key(self):
        # Worst first, then by location for stable output.
        return (-int(self.severity), self.category.value, self.file, self.tool_index, self.tool)


@dataclass
class ScanResult:
    root: str
    findings: list = field(default_factory=list)
    scanned_files: int = 0
    manifests: int = 0
    tools: int = 0
    grade: str = "A"
    grade_score: int = 100

    def counts(self) -> dict:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out
