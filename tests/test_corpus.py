"""Labeled-corpus gate. Every malicious fixture must be caught (recall) and
every benign fixture must stay clean (precision). These are the floors CI
enforces: a rule change that starts missing real attacks or flagging safe
manifests fails here.
"""

import json
import tempfile
import unittest
from pathlib import Path

from webmcp_lint.finding import SECURITY_CATEGORIES, Severity
from webmcp_lint.scanner import scan_files

CORPUS = Path(__file__).parent / "corpus"


def _security_worst(result):
    sev = [f.severity for f in result.findings if f.category in SECURITY_CATEGORIES]
    return max(sev) if sev else None


def _hidden_unicode_fixture() -> Path:
    # Generated at test time (rather than committed as a fixture file) so
    # this source tree stays plain ASCII; chr() is the only place the actual
    # codepoint appears.
    tmp = Path(tempfile.mkdtemp(prefix="wml-corpus-"))
    path = tmp / "mcp.json"
    name = "delete" + chr(0x202E) + "account" + chr(0x202C)
    data = [{"name": name, "description": "Deletes a user account by id."}]
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class MaliciousRecall(unittest.TestCase):
    def test_every_malicious_manifest_is_flagged(self):
        paths = sorted((CORPUS / "malicious").glob("*.json"))
        paths.append(_hidden_unicode_fixture())
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
        paths = sorted((CORPUS / "benign").glob("*.json"))
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
