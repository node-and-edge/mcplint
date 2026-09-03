"""The entrypoint of the mcplint CLI.

Argument parsing, dispatch and exit codes only. Anything that looks like
analysis belongs in a rule; anything that looks like formatting or file access
belongs in `core.py`. Each subcommand below should read as a paragraph you can
check against the documented behaviour without going anywhere else.
"""

import argparse
import json
import sys
from pathlib import Path

from mcplint.core import (
    MEDIUM,
    SEVERITY_ORDER,
    Finding,
    Tool,
    default_baseline_path,
    load_baseline,
    load_tools_from_json,
    render_text,
    run_all,
    save_baseline,
)
from mcplint.rules.pinning import check_against_baseline, fingerprint_tools

# A scan exits non-zero when it finds anything at least this severe, so the tool
# is useful in CI with no extra flags. Stated explicitly here rather than left
# implicit in a comparison somewhere.
FAIL_ON = MEDIUM

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BAD_INPUT = 2

# Everything that can go wrong reading a tool list or a baseline off disk.
# Collected here so the three subcommands cannot drift apart on what counts as
# bad input versus what counts as a finding.
INPUT_ERRORS = (OSError, json.JSONDecodeError, TypeError, ValueError)


def build_parser() -> argparse.ArgumentParser:
    """Define the CLI surface: scan, pin and diff, each taking one path."""
    parser = argparse.ArgumentParser(
        prog="mcplint",
        description="Static linter for MCP server tool definitions.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="run every rule over a tools.json file")
    scan.add_argument("path", help="path to a JSON file holding a tools/list response")

    pin = subcommands.add_parser(
        "pin",
        help="record the current tool definitions, to compare against later",
    )
    pin.add_argument("path", help="path to a JSON file holding a tools/list response")
    _add_baseline_argument(pin)

    diff = subcommands.add_parser(
        "diff",
        help="report what changed since this server was pinned",
    )
    diff.add_argument("path", help="path to a JSON file holding a tools/list response")
    _add_baseline_argument(diff)

    return parser


def _add_baseline_argument(subcommand: argparse.ArgumentParser) -> None:
    """The `--baseline` flag, worded identically on both commands that take it."""
    subcommand.add_argument(
        "--baseline",
        metavar="PATH",
        default=None,
        help="baseline file to write or read (default: alongside the tool list)",
    )


def main(argv: list[str] | None = None) -> int:
    """Run a subcommand and return the process exit code."""
    args = build_parser().parse_args(argv)
    _widen_output_encoding()

    try:
        tools = load_tools_from_json(args.path)
    except INPUT_ERRORS as error:
        print(f"mcplint: could not read {args.path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.command == "pin":
        return _pin(tools, args.path, args.baseline)
    if args.command == "diff":
        return _diff(tools, args.path, args.baseline)
    return _report(run_all(tools), len(tools))


def _pin(tools: list[Tool], source: str, baseline: str | None) -> int:
    """Write the current definitions to a baseline and say where they went."""
    path = Path(baseline) if baseline else default_baseline_path(source)
    try:
        save_baseline(path, fingerprint_tools(tools), source)
    except OSError as error:
        print(f"mcplint: could not write {path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    noun = "tool" if len(tools) == 1 else "tools"
    print(f"Pinned {len(tools)} {noun} to {path}")
    return EXIT_OK


def _diff(tools: list[Tool], source: str, baseline: str | None) -> int:
    """Compare the current definitions against a baseline written earlier."""
    path = Path(baseline) if baseline else default_baseline_path(source)
    try:
        pinned = load_baseline(path)
    except INPUT_ERRORS as error:
        print(f"mcplint: could not read baseline {path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    return _report(check_against_baseline(tools, pinned), len(tools))


def _report(findings: list[Finding], tool_count: int) -> int:
    """Print findings and turn the worst of them into an exit code."""
    print(render_text(findings, tool_count))

    worst = max((SEVERITY_ORDER[finding.severity] for finding in findings), default=-1)
    return EXIT_FINDINGS if worst >= SEVERITY_ORDER[FAIL_ON] else EXIT_OK


def _widen_output_encoding() -> None:
    """Let the process print any character a scan turned up.

    A Windows console defaults to cp1252, which cannot encode a Cyrillic tool
    name -- so printing one raises `UnicodeEncodeError` and the scan dies on
    exactly the finding it exists to report. A linter that looks for strange
    characters has to survive finding one, so widen the stream rather than
    narrow the finding.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


if __name__ == "__main__":
    sys.exit(main())
