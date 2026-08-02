"""docs/rules.md drift check: every RULE_ID in the code appears as a heading
in the doc, and the doc documents nothing that no longer exists. Also checks
that every rule carries the metadata the SARIF output publishes."""

import re
import unittest
from pathlib import Path

from webmcp_lint.rules import RULE_IDS, RULE_META, RULE_MODULES

ROOT = Path(__file__).parent.parent


def _rule_ids_in_code():
    ids = set()
    for py in (ROOT / "webmcp_lint" / "rules").glob("*.py"):
        if py.name in ("__init__.py", "_util.py"):
            continue
        m = re.search(r'^RULE_ID\s*=\s*["\']([^"\']+)["\']', py.read_text(encoding="utf-8"), re.MULTILINE)
        if m:
            ids.add(m.group(1))
    return ids


def _rule_ids_in_doc():
    doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    return set(re.findall(r"^##\s+(WML-\d+)", doc, re.MULTILINE))


class RulesDoc(unittest.TestCase):
    def test_every_rule_is_documented(self):
        undocumented = _rule_ids_in_code() - _rule_ids_in_doc()
        self.assertFalse(undocumented, f"in code but not docs/rules.md: {sorted(undocumented)}")

    def test_doc_has_no_ghost_rules(self):
        ghosts = _rule_ids_in_doc() - _rule_ids_in_code()
        self.assertFalse(ghosts, f"in docs/rules.md but not code: {sorted(ghosts)}")

    def test_doc_is_not_empty(self):
        self.assertGreaterEqual(len(_rule_ids_in_doc()), 5)

    def test_registry_matches_the_rule_modules_on_disk(self):
        self.assertEqual(set(RULE_IDS), _rule_ids_in_code())

    def test_every_rule_has_sarif_metadata(self):
        # The Security tab shows a bare rule id without these, so a new rule
        # that forgets them ships a worse experience than the one it improves.
        for module in RULE_MODULES:
            with self.subTest(rule=module.RULE_ID):
                title, summary = RULE_META[module.RULE_ID]
                self.assertTrue(title.strip(), "TITLE is empty")
                self.assertGreater(len(summary.strip()), 20, "SUMMARY is too thin")


if __name__ == "__main__":
    unittest.main()
