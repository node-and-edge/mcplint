"""The entrypoint of the mcplint CLI.

Argument parsing and exit codes only. Anything that looks like analysis belongs
in a rule; anything that looks like formatting belongs in `render.py`.
"""

import argparse
import json
import sys

from mcplint.core import MEDIUM, SEVERITY_ORDER, load_tools_from_json, render_text, run_all

# A scan exits non-zero when it finds anything at least this severe, so the tool
# is useful in CI with no extra flags. Stated explicitly here rather than left
# implicit in a comparison somewhere.
FAIL_ON = MEDIUM

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_BAD_INPUT = 2


def build_parser() -> argparse.ArgumentParser:
    """Define the CLI surface: one `scan` subcommand taking one path."""
    parser = argparse.ArgumentParser(
        prog="mcplint",
        description="Static linter for MCP server tool definitions.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a static tools.json file")
    scan.add_argument("path", help="path to a JSON file holding a tools/list response")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run a scan and return the process exit code."""
    args = build_parser().parse_args(argv)

    try:
        tools = load_tools_from_json(args.path)
    except (OSError, json.JSONDecodeError, TypeError) as error:
        print(f"mcplint: could not read {args.path}: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT

    findings = run_all(tools)
    print(render_text(findings, len(tools)))

    worst = max((SEVERITY_ORDER[finding.severity] for finding in findings), default=-1)
    return EXIT_FINDINGS if worst >= SEVERITY_ORDER[FAIL_ON] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
