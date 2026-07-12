# Security

webmcp-lint reads a WebMCP tool manifest and reports what's wrong with it
before a site ships it. Parsing is `json.loads` plus text analysis of names,
descriptions, and schemas. It never fetches the manifest from the network,
never registers or calls a tool, and never executes anything it reads.

Manifests are untrusted by definition - auditing a third party's manifest is
normal use, and some of those manifests will be actively malicious. A manifest
crafted to crash the linter, hang it, or smuggle terminal escape sequences
into the report is a vulnerability in webmcp-lint. So is a bypass with teeth:
a manifest that contains one of the patterns this tool explicitly claims to
catch, hidden in a way that makes the lint pass. Novel injection techniques it
has no check for yet? Regular issue, not a vulnerability - send them over
anyway.

## Reporting a vulnerability

Please don't open a public issue for security problems. Use GitHub's private
reporting instead:

https://github.com/munzzyy/webmcp-lint/security/advisories/new

Include what you found, how to reproduce it, and the impact you'd expect.

## Supported versions

Fixes land on the latest tagged version; there's no backport policy.
