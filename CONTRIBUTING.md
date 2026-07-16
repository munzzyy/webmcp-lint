# Contributing

Thanks for looking at this. It's a small, single-purpose tool and contributions are welcome.

## Setup

```
git clone https://github.com/munzzyy/webmcp-lint
cd webmcp-lint
```

There's nothing to install. webmcp-lint is pure standard library, and so is its test suite.

## Running the tests

```
python -m unittest discover -s tests -t .
```

That's the whole suite: unit tests per rule, engine tests, and a labeled corpus in `tests/corpus/`. CI runs the same command across Linux, macOS, and Windows on Python 3.9 through 3.13.

## Adding or fixing a rule

Every rule change lands with a fixture, so coverage only goes up:

- Something dangerous slipped through? Add a manifest under `tests/corpus/malicious/`. The corpus test asserts every malicious fixture gets at least a HIGH finding and never grades A or B.
- A false positive? Add a clean manifest under `tests/corpus/benign/`. The corpus test asserts every benign fixture stays free of HIGH findings and grades A or B.

If you fix a bug with no fixture attached, it can silently come back. A fixture is how the fix stays fixed.

New rules also need an entry in `docs/rules.md` with the same `RULE_ID` used in code; a test checks the two stay in sync.

Keep rules specific. A pattern that fires on an ordinary tool description is worse than one that misses an edge case, because noise trains people to ignore the tool.

## Zero dependencies

webmcp-lint has no runtime dependencies and that's a feature. If a change needs a new package, that's a reason to reconsider the change, not a to-do.

## License

By opening a PR you agree your contribution is offered under the project's MIT license.
