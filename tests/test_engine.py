"""Engine tests: manifest loading, target resolution, grading, reporting, CLI."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from webmcp_lint import cli
from webmcp_lint.discovery import resolve_targets
from webmcp_lint.finding import Category, Finding, Severity
from webmcp_lint.grade import grade
from webmcp_lint.manifest import load
from webmcp_lint.report import render_json, render_sarif
from tests._helpers import scan_manifest, scan_raw, scan_tools


class ManifestLoading(unittest.TestCase):
    def _write(self, text: str) -> Path:
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text(text, encoding="utf-8")
        return p

    def test_bare_array(self):
        m = load(self._write('[{"name": "a", "description": "d"}]'))
        self.assertTrue(m.ok)
        self.assertEqual(len(m.tools), 1)
        self.assertEqual(m.tools[0].name, "a")

    def test_tools_object(self):
        m = load(self._write('{"tools": [{"name": "a", "description": "d"}]}'))
        self.assertTrue(m.ok)
        self.assertEqual(len(m.tools), 1)

    def test_malformed_json(self):
        m = load(self._write("{not json"))
        self.assertFalse(m.ok)
        self.assertIn("invalid JSON", m.parse_error)

    def test_not_utf8(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_bytes(b"\xff\xfe[bad utf8")
        m = load(p)
        self.assertFalse(m.ok)
        self.assertIn("UTF-8", m.parse_error)

    def test_no_tools_array(self):
        m = load(self._write('{"name": "not a tool list"}'))
        self.assertFalse(m.ok)
        self.assertIn("tools", m.structure_error)

    def test_tools_field_wrong_type(self):
        m = load(self._write('{"tools": "nope"}'))
        self.assertFalse(m.ok)

    def test_non_dict_tool_entry_becomes_empty(self):
        m = load(self._write('["not-an-object"]'))
        self.assertTrue(m.ok)
        self.assertEqual(m.tools[0].name, "")
        self.assertEqual(m.tools[0].raw, {})

    def test_missing_input_schema_tracked(self):
        m = load(self._write('[{"name": "a", "description": "d"}]'))
        self.assertFalse(m.tools[0].has_input_schema)

    def test_null_input_schema_is_present_but_none(self):
        m = load(self._write('[{"name": "a", "description": "d", "inputSchema": null}]'))
        self.assertTrue(m.tools[0].has_input_schema)
        self.assertIsNone(m.tools[0].input_schema)

    def test_missing_file(self):
        m = load(Path("/no/such/manifest/mcp.json"))
        self.assertFalse(m.ok)
        self.assertIn("stat", m.parse_error)


class TargetResolution(unittest.TestCase):
    def test_literal_file(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text("[]", encoding="utf-8")
        self.assertEqual(resolve_targets(str(p)), [p])

    def test_directory_finds_well_known_name(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "mcp.json").write_text("[]", encoding="utf-8")
        found = resolve_targets(str(tmp))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "mcp.json")

    def test_directory_with_nothing_found(self):
        tmp = Path(tempfile.mkdtemp())
        self.assertEqual(resolve_targets(str(tmp)), [])

    def test_glob_pattern(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "a.json").write_text("[]", encoding="utf-8")
        (tmp / "b.json").write_text("[]", encoding="utf-8")
        found = resolve_targets(str(tmp / "*.json"))
        self.assertEqual(len(found), 2)

    def test_no_match(self):
        self.assertEqual(resolve_targets("/no/such/path/*.json"), [])


class Grading(unittest.TestCase):
    def _f(self, sev, cat=Category.EXEC):
        return Finding("R", cat, sev, "t", "d", "f")

    def test_clean_is_a(self):
        g, score = grade([])
        self.assertEqual((g, score), ("A", 100))

    def test_high_caps_below_b(self):
        g, score = grade([self._f(Severity.HIGH)])
        self.assertIn(g, ("C", "D", "F"))
        self.assertLessEqual(score, 76)

    def test_critical_is_f(self):
        g, _ = grade([self._f(Severity.CRITICAL)])
        self.assertEqual(g, "F")

    def test_hygiene_findings_dont_affect_grade(self):
        g, score = grade([self._f(Severity.HIGH, cat=Category.HYGIENE)])
        self.assertEqual((g, score), ("A", 100))

    def test_many_mediums_erode_score(self):
        g, score = grade([self._f(Severity.MEDIUM) for _ in range(5)])
        self.assertLess(score, 100)


class Reporting(unittest.TestCase):
    def test_json_is_valid_and_complete(self):
        r = scan_tools([{"name": "getX", "description": "reads a page and returns raw html"}])
        payload = json.loads(render_json(r))
        self.assertEqual(payload["tool"], "webmcp-lint")
        self.assertIn("grade", payload)
        self.assertTrue(payload["findings"])
        self.assertIn("severity", payload["findings"][0])

    def test_sarif_is_valid(self):
        r = scan_tools([{"name": "runShell", "description": "runs arbitrary shell commands"}])
        doc = json.loads(render_sarif(r))
        self.assertEqual(doc["version"], "2.1.0")
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "webmcp-lint")
        self.assertIn(doc["runs"][0]["results"][0]["level"], ("error", "warning", "note"))


class CLI(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_clean_manifest_exit_zero(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text(json.dumps([{
            "name": "createOrder",
            "description": "Create a new order for the given items.",
            "inputSchema": {"type": "object", "properties": {"itemId": {"type": "string", "maxLength": 64}}},
        }]), encoding="utf-8")
        code, _ = self._run([str(p), "--no-color"])
        self.assertEqual(code, 0)

    def test_malicious_fails_on_high(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text(json.dumps([{
            "name": "runCommand",
            "description": "Runs any arbitrary shell command.",
        }]), encoding="utf-8")
        code, _ = self._run([str(p), "--fail-on", "high", "--no-color"])
        self.assertEqual(code, 1)

    def test_fail_on_none_exit_zero(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text(json.dumps([{
            "name": "runCommand",
            "description": "Runs any arbitrary shell command.",
        }]), encoding="utf-8")
        code, _ = self._run([str(p), "--fail-on", "none", "--no-color"])
        self.assertEqual(code, 0)

    def test_json_output_parses(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text(json.dumps([{"name": "a", "description": "d"}]), encoding="utf-8")
        code, out = self._run([str(p), "--json"])
        json.loads(out)

    def test_missing_target(self):
        code, _ = self._run(["/no/such/path/here.json", "--no-color"])
        self.assertEqual(code, 2)

    def test_invalid_fail_on(self):
        with self.assertRaises(SystemExit):
            self._run(["/tmp", "--fail-on", "not-a-severity"])

    def test_quiet_mode(self):
        tmp = Path(tempfile.mkdtemp())
        p = tmp / "mcp.json"
        p.write_text(json.dumps([{"name": "a", "description": "d"}]), encoding="utf-8")
        code, out = self._run([str(p), "--quiet", "--fail-on", "none"])
        self.assertIn("/100", out)


if __name__ == "__main__":
    unittest.main()
