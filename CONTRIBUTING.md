# Contributing to mcplint

The short version: new rules are new files, they need a fixture and a test, and the docstring has to explain the attack rather than the regex.

[`MCPLINT_DEVELOPMENT.md`](MCPLINT_DEVELOPMENT.md) is the long version — architecture, coding standards, release process. This file is the part you need to open a first pull request.

## Getting set up

```bash
uv sync                 # creates .venv, installs everything from uv.lock
uv run pytest           # confirm the baseline passes
uv run ruff check .     # confirm lint is clean
uv run mcplint scan examples/vulnerable_demo_server/tools.json   # smoke test
```

No `pip`, no manual venv activation. If you change dependencies in `pyproject.toml`, run `uv lock` and commit the updated lockfile in the same pull request — CI runs `uv sync --frozen` and will fail if they disagree.

## The constraints that make this project what it is

Check a change against these before checking it against anything else. A feature that breaks one of them doesn't belong in mcplint core, however good it is:

- **Zero network calls**, except the one `tools/list` round trip behind `--stdio-command`. No telemetry, no phone-home, no "optional" analytics.
- **Zero LLM dependency.** No rule may need an API key, a model call, or behaviour that is "roughly right, depends on the model". Every finding must be reproducible offline and deterministically.
- **Zero required dependencies** beyond the standard library.
- **Every rule file readable in about five minutes.** If a rule needs more than a docstring and 100–150 lines to explain itself, it's doing too much.
- **No plugin framework, no inheritance hierarchy.** A rule is a file with one function, registered in one tuple. If you find yourself writing an abstract base class, stop.
- **Constants at the top of the file that uses them**, not in a shared config module. Someone should be able to open `rules/injection.py`, see the phrase list, and edit it without hunting.

Two of these are structural rather than promised, and should stay that way: rule modules are handed data and return data, so they *cannot* read a file or open a socket, and everything that can spawn a process lives in `stdio.py`, which nothing under `rules/` imports.

## Adding a rule

This is the main contribution path, so it's worth having as a checklist.

**1. Open an issue first.** Describe the attack or risk category, with a real or realistic example. Rules should map to a named, documented risk — tool poisoning, schema permissiveness, rug pulls — not a hypothetical.

**2. Add a fixture** in `tests/fixtures/` that trips your rule and nothing else. If it accidentally trips an existing rule, that's useful signal — sort out the overlap before merging. `test_registry.py` asserts each single-purpose fixture trips only its own rule, so this is enforced rather than requested.

If your payload contains characters you can't type — invisible ones, tag characters, bidi overrides — generate the fixture with a script rather than trying. Every existing unicode fixture was built that way, and the JSON keeps them as `\uXXXX` escapes so they stay readable in review.

**3. Write the rule** in `rules/`: one function, constants at the top, returns `list[Finding]`.

The docstring is not optional and it is not a summary. It should answer *why this check exists* — what the attack looks like, why it works, and what it costs an attacker. Someone reading your rule file should come away understanding the attack, not just the pattern. That is the one thing this project is for; if the docstring only restates the code, the rule isn't finished.

Say what the rule will miss, too. `injection.py` says outright that it's trivially evaded and points at the rule that covers the gap.

**4. Register it** in the `rules` tuple in `core.py`'s `run_all()`. A rule that isn't in that tuple doesn't run, and nothing else will tell you — `test_registry.py` is the thing that notices.

Use a stable, uppercase, underscore-separated `rule_id` (`INJECTION_PHRASE`, `PERMISSIVE_SCHEMA`) and give it a default severity:

| | |
|---|---|
| `HIGH` | Somebody did this on purpose and it works |
| `MEDIUM` | Wrong, or plausibly an accident that an attacker needs |
| `LOW` | Worth reading. Not an accusation |

**5. Add a line to `RULE_DESCRIPTIONS`** in `report.py`, for the SARIF output. Two tests check this table from both directions, so forgetting it fails the build rather than quietly producing a worse report six months later.

**6. Write the tests.** Assert on `rule_id` and `severity`, never on exact message wording — message text should stay free to improve. Include the negative cases: the clean fixture must still come back empty, and the ordinary thing your rule *shouldn't* flag needs a test saying so. A rule that fires on a normal server is a rule people switch off, and roughly half the tests in `test_schema_permissiveness.py` and `test_config_hygiene.py` exist for that reason.

**7. Update the README's rule table** in the same pull request. Docs and code land together, always.

**8. Run the full check** before opening it:

```bash
uv run ruff check . && uv run ruff format --check . && uv run pytest
```

A rule pull request without a fixture and a test won't be merged, no exceptions. The fixture *is* the proof the rule works, and it's also the best documentation of the attack it catches.

## Adding a phrase or a pattern to an existing rule

Much smaller, and a good first contribution. Widen the constant at the top of the rule file, add a case to its test, done. No issue needed unless you're unsure whether it belongs.

## Style

- Python 3.11+ syntax is fine (`match`, `X | Y` unions).
- Type hints on every public function signature.
- No abbreviations unless they're already standard: `description` not `desc`, `severity` not `sev`.
- Ruff is the only formatter and linter. Don't add a `.flake8` or `black` config.
- No `print()` outside `report.py` and `cli.py`. Rule modules return data; they never print, log, or have side effects.

Comments should explain why something is the way it is, especially when the obvious version would be wrong. `description_outliers.py` spends a paragraph on why it doesn't use a mean, because the mean-based version reviews well and never fires — and someone will eventually try to simplify it back.

## Commits and pull requests

- Branch names: `rule/unicode-confusables`, `fix/schema-walker-nested-objects`, `docs/readme-examples`.
- Commit messages in the imperative, first line under ~72 characters, body explaining *why* if the diff doesn't. `Add zero-width character detection to unicode_anomaly`, not `updates`.
- One logical change per pull request. A new rule is one; a CLI flag is a separate one, even if they feel related.
- A rule, its fixture, its test and its registry entry can be a single commit. Don't bundle an unrelated refactor into it.
- `main` is always releasable.

## Things that won't be merged

Not because they're bad ideas — several are good ones — but because they're a different tool:

- LLM-based or "semantic" analysis
- Telemetry or usage tracking, anonymised or not
- A hosted service, dashboard or SaaS tier
- Dynamic analysis: starting a server and exercising its tools
- A plugin architecture or rule marketplace

If you think one genuinely belongs, open an issue arguing for it. Don't fold it into an unrelated pull request.

## Releasing

Maintainers only, and deliberately manual — a tag is a promise to whoever installs it.

1. `uv run ruff check . && uv run ruff format --check . && uv run pytest` — green locally.
2. Bump `version` in `pyproject.toml` and `__version__` in `src/mcplint/__init__.py`. They must agree; `mcplint --version` reads the second and the wheel reads the first.
3. Update `CHANGELOG.md` in the same pull request as the version bump, not afterwards. Set the date on the heading.
4. Merge to `main` and **wait for CI to be green on `main` itself**, not just on the pull request.
5. `git tag vX.Y.Z && git push origin vX.Y.Z`.
6. `uv build`, then check the wheel before publishing it:
   ```bash
   uv build
   uv run python -m zipfile -l dist/*.whl        # py.typed and LICENSE present, no strays
   uv venv --python 3.11 /tmp/release-check      # somewhere that is not this checkout
   uv pip install --python /tmp/release-check dist/*.whl
   /tmp/release-check/bin/mcplint --version
   ```
   The install check is not ceremony. It is the only step that catches a package which imports fine from the source tree and not from the wheel.
7. `uv publish`.
8. Bump the `rev:` in the README's pre-commit example to the new tag.

Pre-1.0, breaking changes are allowed but must be called out plainly in the changelog rather than buried.

## Reporting a vulnerability in mcplint itself

Open a regular issue for anything you find in the rules — a false negative is a bug, not a secret.

If you find something where mcplint *itself* is the risk — a way to make it execute something while scanning, or leak what it read — please email the maintainers rather than filing publicly, and give us a chance to fix it first. A security linter that can be turned into a payload is a worse problem than the ones it detects.
