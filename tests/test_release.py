"""The version lives in several files and a release needs all of them to
agree. Regex only, so this runs on Python 3.9 without tomllib."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _pyproject_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.MULTILINE)
    assert m, "no version in pyproject.toml"
    return m.group(1)


class VersionsAgree(unittest.TestCase):
    def test_package_version_matches_pyproject(self):
        m = re.search(r'^__version__\s*=\s*"([^"]+)"', _read("webmcp_lint/__init__.py"), re.MULTILINE)
        self.assertEqual(m.group(1), _pyproject_version())

    def test_readme_pins_match_pyproject(self):
        readme = _read("README.md")
        pins = re.findall(r"munzzyy/webmcp-lint@v(\d+\.\d+\.\d+)", readme)
        pins += re.findall(r"^\s*rev:\s*v(\d+\.\d+\.\d+)", readme, re.MULTILINE)
        self.assertGreaterEqual(len(pins), 4, "README pins went missing")
        self.assertEqual(set(pins), {_pyproject_version()})

    def test_action_ref_default_matches_pyproject_if_set(self):
        m = re.search(r'^  ref:\n(?:    .*\n)*?    default:\s*"([^"]*)"', _read("action.yml"), re.MULTILINE)
        self.assertIsNotNone(m, "action.yml has no ref input")
        if m.group(1):
            self.assertEqual(m.group(1).lstrip("v"), _pyproject_version())

    def test_changelog_has_a_heading_for_this_version(self):
        headings = re.findall(r"^## (\d+\.\d+\.\d+)", _read("CHANGELOG.md"), re.MULTILINE)
        self.assertIn(_pyproject_version(), headings)


if __name__ == "__main__":
    unittest.main()
