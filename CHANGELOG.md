# Changelog

Notable changes to `mcplint`, one entry per release, grouped Added / Changed / Fixed.

Versioning is [semver](https://semver.org/). Pre-1.0 the CLI surface — subcommands, flags, output formats — is not stable, and a breaking change to it is a minor bump. Breaking changes are called out plainly here rather than buried.

## 0.1.0 — 2026-10-06

First release. Everything is new, so the list below is organised by what it does for you rather than by category.

### Six rules

Each in its own file, each opening with a "why this rule exists" section that explains the attack rather than the regex.

- **`INJECTION_PHRASE`** — known instruction-hijack phrasing in a tool description: "ignore previous instructions", fake `<system>` tags, "don't tell the user".
- **`UNICODE_INVISIBLE` / `UNICODE_BIDI` / `UNICODE_MIXED_SCRIPT`** — text you cannot see. Zero-width characters, Unicode tag characters (U+E0000–E007F, which decode to ASCII and render as nothing), bidi overrides, and Cyrillic lookalikes in a tool name.
- **`PERMISSIVE_SCHEMA`** — free-text string parameters with no `enum`, `pattern`, `maxLength` or `format`, when the name suggests a shell, a path, a URL or a query. Walks nested objects, array items and union branches, and reports a dotted path.
- **`DESCRIPTION_OUTLIER`** — descriptions far longer than the rest of the same server's, measured against the median with the median absolute deviation.
- **`SHADOWED_TOOL_NAME`** and, via `pin` / `diff`, **`TOOL_ADDED` / `TOOL_REMOVED` / `TOOL_REDEFINED`** — two tools claiming one name, and a tool that quietly became a different tool under a name you already reviewed.
- **`CONFIG_SHELL_LAUNCH` / `CONFIG_PLAINTEXT_SECRET` / `CONFIG_INSECURE_TRANSPORT` / `CONFIG_NO_AUTH`** — how a server *starts*, before any tool description is involved.

### Three subcommands

- `mcplint scan` — run every rule. Takes any number of files.
- `mcplint pin` — record a fingerprint per tool, to compare against later.
- `mcplint diff` — report what changed since pinning. Baselines store only hashes and a length, never description text.

### Three ways in

- A static JSON export of a `tools/list` response.
- A live server, via `--stdio-command` — mcplint runs the client handshake, reads the menu, and kills the process. It never calls a tool and never sends anything it read anywhere.
- This machine's own MCP client configuration, via `--known-configs`. Reading a config never starts anything found in it.

### Three ways out

- Text, for a terminal. Invisible characters print as their codepoints, because a poisoned name that renders clean in the report would defeat the point of having one.
- `--format json`, for a script.
- `--format sarif`, valid SARIF 2.1.0, for GitHub code scanning.

Plus `--fail-on {low,medium,high,never}` to move the exit threshold, and `--quiet` for a CI step that only branches on the result. Neither the format nor `--quiet` changes the exit code.

### Everything else

- `.pre-commit-hooks.yaml` with two hooks, so a poisoned description is blocked while it is still a staged change rather than after it is deployed.
- `examples/vulnerable_demo_server/` — a runnable, deliberately poisoned MCP server carrying one attack per rule, with a README explaining why each one works. It is inert: every payload is text in a description field, which is how tool poisoning actually works and why a static linter can catch it.
- CI across Python 3.11–3.14 on Linux, Windows and macOS.

### Constraints this release keeps

Stated here because they are the product, not implementation detail:

- **Zero required dependencies** beyond the standard library.
- **Zero network calls**, except the one `tools/list` round trip you asked for with `--stdio-command`. Structural rather than aspirational: everything that can spawn a process lives in `stdio.py`, nothing under `rules/` imports it, and it imports no rule.
- **Zero LLM calls**, under any flag. Every finding is reproducible from text analysis, offline, deterministically.
- **No telemetry**, anonymised or otherwise.
