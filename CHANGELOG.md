# Changelog

Notable changes in each release. If an upgrade broke something for you,
please open an issue at https://github.com/munzzyy/webmcp-lint/issues.

## 0.2.0 (unreleased)

- Lints JS and HTML source directly. A `.js`, `.mjs`, `.html` or `.htm` target is scanned for `registerTool({...})` calls, and a directory with no JSON manifest falls back to its `index.html`, `index.htm`, `mcp.js` or `webmcp.js`.
- The source scanner tokenizes the file instead of patching the literal into JSON. Calls with an `execute` callback (arrow, method or function) are read, and a URL, an apostrophe in a comment, a raw tab or a JS escape in a string no longer makes a tool disappear. Calls inside comments or strings and `unregisterTool(` are ignored. HTML is split up the way a browser splits it, so `<!-->`, `--!>` or a `<!--` inside an attribute or a `<style>` cannot hide a `<script>`, and a `<script>` inside inline SVG is read.
- A `registerTool` call that cannot be read (a variable, a spread, `${...}`) is reported as a HIGH WML-006 finding with its line number instead of being skipped. So is a call in an HTML attribute such as `onclick`, inside a `${...}`, or after a `/` the tokenizer could not tell was a regex or a division. `--ignore` cannot drop it. A file where no call can be read grades F.
- `--recursive` / `-r` also searches subdirectories of a directory target, skipping `node_modules`, `.git`, `dist`, `build` and virtualenvs.
- Several targets in one run (`webmcp-lint mcp.json .well-known/mcp.json`). This fixes the pre-commit hook when more than one manifest is staged.
- Deeply nested JSON or JS no longer crashes the run. If scanning one file raises anyway, that file gets a HIGH WML-006 finding naming the error and the other files are still reported.
- Fixed three inputs that could hang the linter for minutes or hours: a description repeating "always run", a long run of punctuation such as `/* /* /*`, and thousands of unclosed `registerTool(` calls.
- WML-003 catches `don't tell the user`, `don't let the user know` and `without letting the user know`, and no longer flags `never show the user's card number`.
- WML-005 no longer fires on names like `getSystemStatus` or on a search tool that "matches any query". `runSystemCommand`, `openShell` and "executes any query" are still flagged.
- The human report escapes bidi controls, tag characters and zero-width characters, so a tool name cannot reorder the line that reports it.
- SARIF rules carry `security-severity` and a `security` tag, and findings from JS or HTML source point at the line of their `registerTool` call. Fingerprints are unchanged, so dismissed alerts stay dismissed.
- The GitHub Action installs webmcp-lint from its own copy, so pinning the action pins the linter. `ref` now defaults to empty, and a new `upload-sarif` input turns the Security tab upload off.
- A PyPI publish workflow, which refuses to publish when the release tag and the package version disagree.
- Relicensed to GPL-3.0-or-later. Releases up to 0.1.1 stay under MIT.

## 0.1.1 - 2026-08-02

- A composite GitHub Action that scans, uploads SARIF to the Security tab and gates the job on `fail-on`.
- A manifest that cannot be read is a HIGH finding, marked not scanned, and grades F with a score of zero. Manifests saved with a UTF-8 BOM or as UTF-16 are read, and a file over the 2 MB limit says so instead of reporting a JSON error.
- WML-003, WML-004 and WML-008 read the whole `inputSchema`, including parameter descriptions and nested properties.
- New rules: WML-009 (Chrome's size budgets), WML-010 (injection split across tools or hidden in base64, hex or percent encoding) and WML-011 (deprecated `navigator.modelContext`).
- WML-008 also catches raw control characters such as ESC.
- `--ignore` suppresses a rule everywhere, but never a manifest that could not be read.
- The human report escapes terminal control characters, and output to a cp1252 stream on Windows no longer crashes.
- Usage errors exit 2, and `--quiet` cannot be combined with `--json` or `--sarif`.

## 0.1.0 - 2026-07-15

- First release: rules WML-001 to WML-008, human, JSON and SARIF output, a letter grade, and a pre-commit hook.
