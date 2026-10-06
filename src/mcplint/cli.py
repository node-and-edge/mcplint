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

from mcplint import __version__
from mcplint.config_scan import discover_servers
from mcplint.core import (
    MEDIUM,
    SEVERITY_ORDER,
    Finding,
    Tool,
    default_baseline_path,
    load_baseline,
    load_tools_from_json,
    run_all,
    save_baseline,
)
from mcplint.report import render_json, render_sarif, render_text
from mcplint.rules.config_hygiene import check_config_hygiene
from mcplint.rules.pinning import check_against_baseline, fingerprint_tools
from mcplint.stdio import DEFAULT_TIMEOUT_SECONDS, StdioError, load_tools_from_stdio

# A run exits non-zero when it finds anything at least this severe, so the tool
# is useful in CI with no extra flags. Stated explicitly here rather than left
# implicit in a comparison somewhere, and overridable with --fail-on.
FAIL_ON = MEDIUM

# What --fail-on accepts. `never` is for a job that wants the report published
# without the build going red -- the finding is still printed, and the exit
# code still tells the truth about whether reading it was optional.
FAIL_ON_CHOICES = ("low", "medium", "high", "never")
DEFAULT_FAIL_ON = FAIL_ON.lower()

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BAD_INPUT = 2

# Everything that can go wrong reading a tool list or a baseline off disk.
# Collected here so the three subcommands cannot drift apart on what counts as
# bad input versus what counts as a finding.
INPUT_ERRORS = (OSError, json.JSONDecodeError, TypeError, ValueError)

# How findings can be printed. Text is what a person reads; the other two exist
# so that something other than a person can read them without parsing text.
FORMATS = ("text", "json", "sarif")
DEFAULT_FORMAT = "text"


def build_parser() -> argparse.ArgumentParser:
    """Define the CLI surface: scan, pin and diff over a file or a live server."""
    parser = argparse.ArgumentParser(
        prog="mcplint",
        description="Static linter for MCP server tool definitions.",
        epilog=(
            "Input comes from one of three places: a JSON file, a live server "
            "started with --stdio-command, or this machine's own client "
            "configuration with --known-configs. Spawning a server is the only "
            "thing mcplint does that is not arithmetic on a file, and it happens "
            "only when you name the command yourself -- reading a config never "
            "starts anything found in it."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcplint {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser(
        "scan",
        help="run every rule over a tool list",
        description="Run every rule over a tool list and report what looks wrong.",
    )
    _add_source_arguments(scan, many=True)
    _add_format_argument(scan)
    _add_quiet_argument(scan)

    pin = subcommands.add_parser(
        "pin",
        help="record the current tool definitions, to compare against later",
        description="Record a fingerprint of every tool, to compare against later.",
    )
    _add_source_arguments(pin, known_configs=False)
    _add_baseline_argument(pin)
    _add_quiet_argument(pin)

    diff = subcommands.add_parser(
        "diff",
        help="report what changed since this server was pinned",
        description="Report tools added, removed or silently redefined since pinning.",
    )
    _add_source_arguments(diff, known_configs=False)
    _add_baseline_argument(diff)
    _add_format_argument(diff)
    _add_quiet_argument(diff)

    return parser


def _add_source_arguments(
    subcommand: argparse.ArgumentParser, known_configs: bool = True, many: bool = False
) -> None:
    """Where the input comes from, worded identically on every command.

    `scan` takes any number of paths, because a pre-commit hook hands its tool
    every staged file that matched and expects it to cope. `pin` and `diff`
    take one: a baseline describes a single server, and a command that quietly
    pinned four of them into one file would be worse than one that refused.

    `--known-configs` is offered only by `scan` for the same reason -- pinning
    a config file is a different question with a different answer, and a flag
    that could not be honoured is worse than one that is absent.
    """
    subcommand.add_argument(
        "path",
        nargs="*" if many else "?",
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


def _add_format_argument(subcommand: argparse.ArgumentParser) -> None:
    """How to print findings. Not offered by `pin`, which reports no findings."""
    subcommand.add_argument(
        "--format",
        choices=FORMATS,
        default=DEFAULT_FORMAT,
        help=f"how to print findings (default: {DEFAULT_FORMAT})",
    )
    subcommand.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help=f"lowest severity that exits non-zero (default: {DEFAULT_FAIL_ON})",
    )


def _add_quiet_argument(subcommand: argparse.ArgumentParser) -> None:
    """Say nothing; the exit code is the whole report."""
    subcommand.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print nothing, and let the exit code carry the answer",
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
    args = parser.parse_args(_bind_stdio_args(sys.argv[1:] if argv is None else argv))
    _widen_output_encoding()
    _check_source(parser, args)

    if getattr(args, "known_configs", False):
        return _scan_known_configs(args)

    if args.command == "scan" and args.path:
        return _scan_each(args)

    try:
        tools = _load_tools(args)
    except StdioError as error:
        print(f"mcplint: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT
    except INPUT_ERRORS as error:
        print(f"mcplint: could not read {_one_path(args)}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.command == "pin":
        return _pin(tools, args, parser)
    if args.command == "diff":
        return _diff(tools, args, parser)
    return _report(run_all(tools), len(tools), args)


def _bind_stdio_args(argv: list[str]) -> list[str]:
    """Join each `--stdio-arg` to the word after it, so that word may start with a dash.

    argparse reads `--stdio-arg -y` as a flag with its value missing, followed by
    an option it has never heard of -- and `npx -y some-server` is the launch line
    nearly every MCP server's README gives. `--stdio-arg=-y` is the spelling
    argparse accepts, so that is what this hands it. A trailing `--stdio-arg`
    with nothing after it is left alone, for argparse to complain about.
    """
    bound: list[str] = []
    words = iter(argv)
    for word in words:
        value = next(words, None) if word == "--stdio-arg" else None
        bound.append(word if value is None else f"{word}={value}")
    return bound


def _scan_each(args: argparse.Namespace) -> int:
    """Scan several files in one run, reporting each and failing on the worst.

    Findings are tagged with the file they came from, so a hook that hands over
    forty staged files still produces a report you can act on. The exit code is
    the worst across all of them -- one poisoned file in forty is a failed run.
    """
    worst = EXIT_OK
    findings: list[Finding] = []
    total = 0

    for path in args.path:
        try:
            tools = load_tools_from_json(path)
        except INPUT_ERRORS as error:
            print(f"mcplint: could not read {path}: {error}", file=sys.stderr)
            worst = EXIT_BAD_INPUT
            continue

        for finding in run_all(tools):
            finding.source = str(path)
            findings.append(finding)
        total += len(tools)

    code = _report(findings, total, args, source=_scan_label(args), show_source=len(args.path) > 1)
    return worst if worst == EXIT_BAD_INPUT else code


def _scan_label(args: argparse.Namespace) -> str:
    """What to call the scan as a whole, when a finding does not name a file."""
    return args.path[0] if len(args.path) == 1 else f"{len(args.path)} files"


def _scan_known_configs(args: argparse.Namespace) -> int:
    """Check this machine's configured servers, without starting any of them."""
    servers, sources = discover_servers()

    # The preamble is orientation for a person and noise in a data format, so
    # it is printed only when a person is the one reading.
    if args.format == "text" and not args.quiet:
        if not sources:
            print("No MCP client configuration found on this machine.")
            return EXIT_OK
    elif not sources and args.format == "text":
        return EXIT_OK
        noun = "server" if len(servers) == 1 else "servers"
        where = "file" if len(sources) == 1 else "files"
        print(f"Found {len(servers)} configured {noun} across {len(sources)} config {where}.")
        for source in sources:
            print(f"  {source}")
        print()

    return _report(
        check_config_hygiene(servers), len(servers), args, subject="servers", source="known-configs"
    )


def _check_source(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Insist on exactly one source, since argparse cannot express that here."""
    chosen = [
        bool(args.path),
        bool(args.stdio_command),
        bool(getattr(args, "known_configs", False)),
    ]
    if isinstance(args.path, list) and len(args.path) > 1 and args.command != "scan":
        parser.error(f"{args.command} takes one tool list at a time")
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
    """Read one tool list from wherever this invocation says it lives."""
    if args.stdio_command:
        return load_tools_from_stdio(args.stdio_command, args.stdio_arg, args.stdio_timeout)
    return load_tools_from_json(_one_path(args))


def _pin(tools: list[Tool], args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Write the current definitions to a baseline and say where they went."""
    path = _baseline_path(args, parser)
    try:
        save_baseline(path, fingerprint_tools(tools), _one_path(args) or args.stdio_command)
    except OSError as error:
        print(f"mcplint: could not write {path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if not args.quiet:
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

    return _report(check_against_baseline(tools, pinned), len(tools), args)


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
        return default_baseline_path(_one_path(args))
    parser.error("--baseline is required when pinning or diffing a --stdio-command server")


def _report(
    findings: list[Finding],
    subject_count: int,
    args: argparse.Namespace,
    subject: str = "tools",
    source: str | None = None,
    show_source: bool = False,
) -> int:
    """Print findings in the requested format and turn the worst into an exit code.

    The exit code does not depend on the format, and `--quiet` changes what is
    printed and nothing else. A CI job that switches to SARIF for nicer
    annotations, or goes quiet because the log was noisy, must not quietly
    stop failing at the same time.
    """
    if not args.quiet:
        chosen = getattr(args, "format", DEFAULT_FORMAT)
        if chosen == "sarif":
            print(render_sarif(findings, source or _source_label(args)))
        elif chosen == "json":
            print(render_json(findings, subject_count, subject))
        else:
            print(render_text(findings, subject_count, subject, show_source=show_source))

    worst = max((SEVERITY_ORDER[finding.severity] for finding in findings), default=-1)
    return EXIT_FINDINGS if worst >= _fail_threshold(args) else EXIT_OK


def _fail_threshold(args: argparse.Namespace) -> int:
    """The severity rank at which this run starts exiting non-zero."""
    choice = getattr(args, "fail_on", DEFAULT_FAIL_ON)
    if choice == "never":
        # Above every rank there is, so nothing reaches it.
        return len(SEVERITY_ORDER)
    return SEVERITY_ORDER[choice.upper()]


def _source_label(args: argparse.Namespace) -> str:
    """What the findings came from, for formats that want to record it."""
    if args.path:
        return _one_path(args)
    return f"mcp-stdio:{args.stdio_command}"


def _one_path(args: argparse.Namespace) -> str:
    """The single path this invocation was given, whatever shape it arrived in."""
    return args.path[0] if isinstance(args.path, list) else args.path


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
