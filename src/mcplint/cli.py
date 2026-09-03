"""The entrypoint of the mcplint CLI.

Argument parsing, dispatch and exit codes only. Anything that looks like
analysis belongs in a rule; anything that looks like formatting or file access
belongs in `core.py`; anything that spawns a process belongs in `stdio.py`.
Each subcommand below should read as a paragraph you can check against the
documented behaviour without going anywhere else.
"""

import argparse
import json
import sys
from pathlib import Path

from mcplint.config_scan import discover_servers
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
from mcplint.rules.config_hygiene import check_config_hygiene
from mcplint.rules.pinning import check_against_baseline, fingerprint_tools
from mcplint.stdio import DEFAULT_TIMEOUT_SECONDS, StdioError, load_tools_from_stdio

# A run exits non-zero when it finds anything at least this severe, so the tool
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
    """Define the CLI surface: scan, pin and diff over a file or a live server."""
    parser = argparse.ArgumentParser(
        prog="mcplint",
        description="Static linter for MCP server tool definitions.",
        epilog=(
            "Every command reads either a JSON file or, with --stdio-command, a "
            "live server. Spawning a server is the only thing mcplint does that "
            "is not arithmetic on a file you already had, and it happens only "
            "when you ask for it by name."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser(
        "scan",
        help="run every rule over a tool list",
        description="Run every rule over a tool list and report what looks wrong.",
    )
    _add_source_arguments(scan)

    pin = subcommands.add_parser(
        "pin",
        help="record the current tool definitions, to compare against later",
        description="Record a fingerprint of every tool, to compare against later.",
    )
    _add_source_arguments(pin, known_configs=False)
    _add_baseline_argument(pin)

    diff = subcommands.add_parser(
        "diff",
        help="report what changed since this server was pinned",
        description="Report tools added, removed or silently redefined since pinning.",
    )
    _add_source_arguments(diff, known_configs=False)
    _add_baseline_argument(diff)

    return parser


def _add_source_arguments(subcommand: argparse.ArgumentParser, known_configs: bool = True) -> None:
    """Where the input comes from, worded identically on every command.

    `--known-configs` is offered only by `scan`: pinning or diffing a config
    file is a different question with a different answer, and pretending
    otherwise would put a flag on a command that could not honour it.
    """
    subcommand.add_argument(
        "path",
        nargs="?",
        help="path to a JSON file holding a tools/list response",
    )
    subcommand.add_argument(
        "--stdio-command",
        metavar="CMD",
        default=None,
        help="instead of a file, run this command as an MCP server and ask it directly",
    )
    subcommand.add_argument(
        "--stdio-arg",
        metavar="ARG",
        action="append",
        default=[],
        help="an argument for --stdio-command; repeat once per argument",
    )
    if known_configs:
        subcommand.add_argument(
            "--known-configs",
            action="store_true",
            help="instead of a tool list, check the MCP servers configured on this machine",
        )
    subcommand.add_argument(
        "--stdio-timeout",
        metavar="SECONDS",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"how long the server gets to answer (default: {DEFAULT_TIMEOUT_SECONDS:.0f})",
    )


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
    parser = build_parser()
    args = parser.parse_args(argv)
    _widen_output_encoding()
    _check_source(parser, args)

    if getattr(args, "known_configs", False):
        return _scan_known_configs()

    try:
        tools = _load_tools(args)
    except StdioError as error:
        print(f"mcplint: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT
    except INPUT_ERRORS as error:
        print(f"mcplint: could not read {args.path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.command == "pin":
        return _pin(tools, args, parser)
    if args.command == "diff":
        return _diff(tools, args, parser)
    return _report(run_all(tools), len(tools))


def _scan_known_configs() -> int:
    """Check this machine's configured servers, without starting any of them."""
    servers, sources = discover_servers()
    if not sources:
        print("No MCP client configuration found on this machine.")
        return EXIT_OK

    noun = "server" if len(servers) == 1 else "servers"
    where = "file" if len(sources) == 1 else "files"
    print(f"Found {len(servers)} configured {noun} across {len(sources)} config {where}.")
    for source in sources:
        print(f"  {source}")
    print()

    return _report(check_config_hygiene(servers), len(servers), subject="servers")


def _check_source(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Insist on exactly one source, since argparse cannot express that here."""
    chosen = [
        bool(args.path),
        bool(args.stdio_command),
        bool(getattr(args, "known_configs", False)),
    ]
    if sum(chosen) > 1:
        parser.error("choose one of: a path, --stdio-command, or --known-configs")
    if not any(chosen):
        parser.error(
            "give a path to a tool list, --stdio-command to ask a server, "
            "or --known-configs to check this machine's configuration"
        )
    if args.stdio_arg and not args.stdio_command:
        parser.error("--stdio-arg has nothing to attach to without --stdio-command")


def _load_tools(args: argparse.Namespace) -> list[Tool]:
    """Read the tool list from wherever this invocation says it lives."""
    if args.stdio_command:
        return load_tools_from_stdio(args.stdio_command, args.stdio_arg, args.stdio_timeout)
    return load_tools_from_json(args.path)


def _pin(tools: list[Tool], args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Write the current definitions to a baseline and say where they went."""
    path = _baseline_path(args, parser)
    try:
        save_baseline(path, fingerprint_tools(tools), args.path or args.stdio_command)
    except OSError as error:
        print(f"mcplint: could not write {path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    noun = "tool" if len(tools) == 1 else "tools"
    print(f"Pinned {len(tools)} {noun} to {path}")
    return EXIT_OK


def _diff(tools: list[Tool], args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Compare the current definitions against a baseline written earlier."""
    path = _baseline_path(args, parser)
    try:
        pinned = load_baseline(path)
    except INPUT_ERRORS as error:
        print(f"mcplint: could not read baseline {path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    return _report(check_against_baseline(tools, pinned), len(tools))


def _baseline_path(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Path:
    """Where this run's baseline lives.

    A file has an obvious answer -- beside itself. A live server does not: a
    command line is not a location, and guessing a filename from one would put
    two different servers in the same baseline the first time somebody ran
    `npx` twice. So say so instead of guessing.
    """
    if args.baseline:
        return Path(args.baseline)
    if args.path:
        return default_baseline_path(args.path)
    parser.error("--baseline is required when pinning or diffing a --stdio-command server")


def _report(findings: list[Finding], subject_count: int, subject: str = "tools") -> int:
    """Print findings and turn the worst of them into an exit code."""
    print(render_text(findings, subject_count, subject))

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
