"""Labeled-corpus gate. Every malicious fixture must be caught (recall) and
every benign fixture must stay clean (precision). These are the floors CI
enforces: a rule change that starts missing real attacks or flagging safe
manifests fails here.
"""

import json
import unittest
from pathlib import Path

from webmcp_lint.finding import SECURITY_CATEGORIES, Severity
from webmcp_lint.scanner import scan_files
from tests._helpers import temp_dir

CORPUS = Path(__file__).parent / "corpus"

# JSON manifests plus JS/HTML source scanned via jsextract.py - a fixture in
# either form gets the same recall/precision floor.
_FIXTURE_GLOBS = ("*.json", "*.html", "*.js")


def _corpus_paths(kind: str):
    paths = []
    for pattern in _FIXTURE_GLOBS:
        paths.extend((CORPUS / kind).glob(pattern))
    return sorted(paths)


def _security_worst(result):
    sev = [f.severity for f in result.findings if f.category in SECURITY_CATEGORIES]
    return max(sev) if sev else None


def _write_generated(name: str, data) -> Path:
    # Generated at test time (rather than committed as a fixture file) so
    # this source tree stays plain ASCII; chr() is the only place the actual
    # codepoint appears.
    path = temp_dir() / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _hidden_unicode_fixture() -> Path:
    name = "delete" + chr(0x202E) + "account" + chr(0x202C)
    return _write_generated(
        "hidden-unicode.json",
        [{"name": name, "description": "Deletes a user account by id."}])


def _hidden_unicode_in_param_fixture() -> Path:
    # Same trick one level down, in a parameter description, which is where a
    # payload goes to get past a scanner that only reads the tool description.
    hint = "The account id" + chr(0x202E) + " to delete" + chr(0x202C)
    return _write_generated("hidden-unicode-param.json", [{
        "name": "closeAccount",
        "description": "Closes an account by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"accountId": {"type": "string", "maxLength": 64,
                                         "description": hint}},
        },
    }])


def _ansi_escape_fixture() -> Path:
    # A name carrying erase-line and cursor-up sequences, which repaint the
    # report over the findings already printed.
    esc = chr(0x1B)
    name = "getData" + esc + "[2K" + esc + "[1A" + esc + "[32mSAFE" + esc + "[0m"
    return _write_generated(
        "ansi-escape.json",
        [{"name": name, "description": "Reads a value."}])


GENERATED = (_hidden_unicode_fixture, _hidden_unicode_in_param_fixture,
             _ansi_escape_fixture)


class MaliciousRecall(unittest.TestCase):
    def test_every_malicious_manifest_is_flagged(self):
        paths = _corpus_paths("malicious")
        paths.extend(make() for make in GENERATED)
        self.assertTrue(paths, "no malicious fixtures found")
        for path in paths:
            with self.subTest(manifest=path.name):
                r = scan_files([path], root=str(path))
                worst = _security_worst(r)
                self.assertIsNotNone(worst, f"{path.name}: nothing flagged")
                self.assertGreaterEqual(
                    worst, Severity.HIGH, f"{path.name}: worst finding {worst} < HIGH")
                # No rule in this tool reaches CRITICAL, so a single HIGH finding
                # caps out at C (see grade.py). The floor that actually matters is
                # that a malicious manifest never grades A or B.
                self.assertNotIn(r.grade, ("A", "B"), f"{path.name}: grade {r.grade} too lenient")


class BenignPrecision(unittest.TestCase):
    def test_every_benign_manifest_is_clean(self):
        paths = _corpus_paths("benign")
        self.assertTrue(paths, "no benign fixtures found")
        for path in paths:
            with self.subTest(manifest=path.name):
                r = scan_files([path], root=str(path))
                loud = [f for f in r.findings
                        if f.category in SECURITY_CATEGORIES and f.severity >= Severity.HIGH]
                self.assertEqual(loud, [], f"{path.name}: false positives {[f.title for f in loud]}")
                self.assertIn(r.grade, ("A", "B"), f"{path.name}: grade {r.grade} - unexpected penalty")


if __name__ == "__main__":
    unittest.main()
