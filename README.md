# mcplint

A tiny, dependency-free static linter for MCP server tool definitions. It reads the tools a server exposes and flags the obvious ways they can go wrong — hidden instructions in descriptions, invisible unicode, schemas that accept anything, tools that silently changed since last time you looked. No network calls beyond the one you were already making to list the tools. No LLM in the loop. No API key. Just text analysis you can read in one sitting.

We built this because every MCP security tool we looked at was, one way or another, a platform. YARA rules plus an LLM judge plus a sandboxed dependency scan plus a dashboard plus an API key you have to trust with your tool descriptions. All of that is genuinely useful and We'd run it too. But before any of that, We wanted something we could `uv sync`, point at a `tools.json`, and have it tell me in half a second whether a description has a zero-width character hiding a prompt injection in it. That tool didn't really exist as its own thing, so here it is.

This is very much in the spirit of the "nano" projects — the whole point is that the code is small enough that you, the user, are expected to actually open it and read it. If you can't understand every rule in `rules/` in about five minutes, We've failed at the one thing this project is supposed to do. Don't trust the tool because We said so — trust it because you read it.

## Why this needed to exist

MCP servers expose a `description` field per tool, and that field gets dropped straight into the model's context with instruction-level authority. Nothing in the protocol distinguishes "this text describes what the tool does" from "this text is a command the model should obey." That's not a bug that's going to get patched — it's a property of how the protocol works, and the people who maintain it have said as much: sanitizing this is on you, the developer, not the spec.

So a tool description can just... contain an instruction. Hidden in whitespace. Hidden behind a zero-width character. Buried in three paragraphs of otherwise-normal-looking text. It'll sit there quietly and fire on every single call, for every user, until somebody happens to go read it by hand. Nobody goes and reads it by hand. That's the whole problem in one sentence.

`mcplint` is the dumbest possible thing that helps: read the tool list, run some plain pattern matching and a bit of `unicodedata` over it, tell you what looks wrong.

## Status

Early. `mcplint scan <file.json>` works end to end today, with the `injection` rule wired through. The other four rules below, the stdio loader, `pin`/`diff`, `--known-configs` and SARIF output are described here as the intended shape of the tool, but are **not implemented yet** — the sections below are the plan, not a changelog.

## What it actually checks

Five checks, each in its own ~100-line file, each doing exactly one thing:

- **`injection.py`** *(implemented)* — keyword/regex matching for known instruction-hijack phrasing ("ignore previous instructions," fake role tags, "don't tell the user," etc). Not clever. Catches the lazy attacks, which — turns out — is most of them.
- **`unicode_anomaly.py`** — zero-width characters, bidi overrides, mixed scripts inside descriptions. Stuff that's invisible to you but not to the model.
- **`schema_permissiveness.py`** — walks each tool's JSON input schema and flags free-text string params with no `enum`/`pattern`/length bound, when the param name smells dangerous (`cmd`, `path`, `url`, `script`, `query`...). This is where the command-injection and SSRF findings tend to live.
- **`description_outliers.py`** — z-score on description length/token density relative to the rest of the server's tool list. Unusually long, instruction-dense descriptions are both a red flag and a context-budget problem.
- **`pinning.py`** — hashes name + description + schema per tool on first run, diffs on every run after. Catches silent redefinition ("rug pulls") and duplicate tool names across servers ("shadowing"), for free, since you're already parsing the list.

That's it. That's the whole tool. Everything else (SARIF export, config auto-discovery, table formatting) is plumbing around these five checks, not additional cleverness.

`mcplint` is the layer you run locally, for free, with nothing installed but Python, before you ever send a tool description to anyone's API. Think of it as the `flake8` to their full CI security suite — narrower, dumber, and fine with that.

## Install

```bash
uv add mcplint
```

Zero required dependencies beyond the Python standard library.

## Usage

Point it at a static export of a server's tool list:

```bash
mcplint scan tools.json
```

Or let it spawn a stdio MCP server itself and pull `tools/list` directly:

```bash
mcplint scan --stdio-command npx --stdio-arg -y --stdio-arg some-mcp-server
```

Baseline the current tool set, then check for silent changes later (rug-pull detection):

```bash
mcplint pin tools.json
# ... time passes ...
mcplint diff tools.json
```

Auto-discover whatever's configured in Claude Desktop / Cursor / etc. on this machine:

```bash
mcplint scan --known-configs
```

CI-friendly output for GitHub code scanning:

```bash
mcplint scan tools.json --format sarif > results.sarif
```

Example output:

```
$ mcplint scan tools.json

  tool: fetch_url
  [HIGH] INJECTION_PHRASE     description contains "ignore previous instructions"
         at byte offset 142

  tool: read_file
  [MED]  PERMISSIVE_SCHEMA    param "path" is unconstrained free-text string
         no enum, pattern, or maxLength set

  tool: run_query
  [LOW]  DESCRIPTION_OUTLIER  description is 4.2x longer than server average

  3 findings across 12 tools. 1 high, 1 medium, 1 low.
```

### Exit codes

So it's useful in CI without extra flags:

| Code | Meaning |
|---|---|
| `0` | scanned fine, nothing at or above `MEDIUM` |
| `1` | at least one finding at `MEDIUM` or `HIGH` |
| `2` | the input couldn't be read or parsed |

## Design notes, for anyone reading the source

- Every finding is a plain dataclass: `rule_id`, `severity`, `tool_name`, `message`, `evidence_snippet`, `remediation`. No inheritance hierarchy, no plugin framework. If you want a new check, copy an existing rule file and change the logic.
- Nothing here calls the network except the one legitimate `tools/list` round trip when you use `--stdio-command`. If you feed it a static JSON file, it makes zero network calls, full stop.
- Nothing here calls an LLM. That's a deliberate constraint, not a missing feature — it's what keeps this at "run before your coffee's ready" speed and "free" cost, and it's what makes the false positives predictable instead of vibes-based.
- The rule thresholds (z-score cutoffs, dangerous param name list, etc.) are constants at the top of each file, not buried in config. Change them, rerun, see what happens. That's the intended workflow.

## What it will miss

Being honest here matters more than being impressive. This will not catch:

- Semantically disguised injections that don't match any keyword pattern (an LLM-judged scanner will do better here)
- Malicious behavior in the tool's actual *implementation* code (that's source-level static/behavioral analysis — different tool, different job)
- Anything requiring live dynamic testing against a running server
- Supply-chain issues in the server's dependencies

If any of those matter to you — and for a production deployment, they probably should — run this alongside a heavier tool, not instead of one.

## Roadmap

Roughly in order of "will actually get built":

- [ ] Config-hygiene check (flag servers with no auth, or stdio commands invoking `bash -c`/`eval` directly)
- [ ] Pre-commit hook mode — block a tool description change before it's committed, not just after deploy
- [ ] A small fixtures set of deliberately poisoned tool defs, for testing and for showing people what an actual attack looks like
- [ ] Maybe a GitHub Action wrapper, if people ask for it

Not planned, on purpose: an LLM analyzer mode, a hosted dashboard, a SaaS tier. If you want those, the tools that already do them do them well — this one's job is to stay small.

## License

Apache License 2.0
