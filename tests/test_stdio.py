"""Tests for the stdio loader, against a real server process.

`fixtures/stdio_server.py` is spawned for each of these rather than mocked, so
the handshake is exercised the way it will actually be used -- including the
parts that only go wrong across a real pipe. No test here reaches the network;
the "server" is a Python script in this repo.

The timing assertions are not incidental. Two of the bugs this module had were
hangs, and a hang does not fail a test suite, it stops one.
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcplint.cli import EXIT_BAD_INPUT, EXIT_FINDINGS, EXIT_OK, main
from mcplint.stdio import StdioError, load_tools_from_stdio

SERVER = str(Path(__file__).parent / "fixtures" / "stdio_server.py")

# Long enough that a slow machine starting a Python process is not a failure,
# short enough that a genuine hang fails the suite instead of stalling it.
PATIENCE = 20.0

# What the hang tests allow themselves to wait. Any real deadlock blows past it.
BRIEF = 1.0


def _serve(mode, timeout=PATIENCE):
    return load_tools_from_stdio(sys.executable, [SERVER, mode], timeout=timeout)


def _cli_source(mode):
    return ["--stdio-command", sys.executable, "--stdio-arg", SERVER, "--stdio-arg", mode]


# --- the happy path ---------------------------------------------------------


def test_a_clean_server_hands_back_its_tools():
    tools = _serve("clean")

    assert [tool.name for tool in tools] == ["read_file", "list_directory", "fetch_url"]


def test_descriptions_and_schemas_survive_the_round_trip():
    read_file = _serve("clean")[0]

    assert "Read a file" in read_file.description
    assert read_file.input_schema["properties"]["path"]["maxLength"] == 4096


def test_log_lines_on_stdout_are_stepped_over():
    # Real servers print startup logging and notifications on the same pipe
    # they answer on. A client that treated the first line it saw as the reply
    # would fail against half the servers in the wild.
    assert len(_serve("noisy")) == 3


def test_a_poisoned_server_reaches_the_rules_intact():
    from mcplint.core import run_all

    findings = run_all(_serve("poisoned"))

    assert len({finding.rule_id for finding in findings}) == 5


# --- the unhappy paths ------------------------------------------------------


def test_a_command_that_does_not_exist_is_reported_not_raised_raw():
    with pytest.raises(StdioError, match="could not start"):
        load_tools_from_stdio("mcplint-nonexistent-command-xyz")


def test_a_server_that_exits_early_quotes_its_own_complaint():
    # The user needs to know *why* the server died, and the server already
    # said so on stderr. Repeating it saves them a second run.
    with pytest.raises(StdioError, match="config file not found"):
        _serve("crash")


def test_a_server_that_refuses_is_reported_as_refusing():
    with pytest.raises(StdioError, match="tools are not enumerable"):
        _serve("error")


def test_a_hanging_server_times_out_instead_of_hanging_the_linter():
    start = time.monotonic()

    with pytest.raises(StdioError, match="in time"):
        _serve("hang", timeout=BRIEF)

    assert time.monotonic() - start < PATIENCE, "the timeout did not fire"


def test_shutting_down_a_hung_server_does_not_deadlock():
    # This is the regression test for a real deadlock: closing an output pipe
    # while the reader thread is blocked on it waits for a lock that the
    # blocked read is holding. The process has to die first. When that ordering
    # was wrong, this call never returned at all.
    start = time.monotonic()

    for _ in range(3):
        with pytest.raises(StdioError):
            _serve("hang", timeout=BRIEF)

    assert time.monotonic() - start < PATIENCE


def test_a_crashed_server_leaves_nothing_running():
    with pytest.raises(StdioError):
        _serve("crash")

    # If shutdown leaked a process, the next spawn of the same script would be
    # competing with it for nothing in particular -- but more to the point, a
    # linter that leaves a subprocess behind on every run is a worse problem
    # than whatever it was linting for.
    assert _serve("clean"), "a later run should still work cleanly"


# --- through the CLI --------------------------------------------------------


def test_scanning_a_live_server_works_end_to_end(capsys):
    exit_code = main(["scan", *_cli_source("poisoned")])

    assert exit_code == EXIT_FINDINGS
    assert "INJECTION_PHRASE" in capsys.readouterr().out


def test_a_clean_live_server_exits_zero(capsys):
    exit_code = main(["scan", *_cli_source("clean")])

    assert exit_code == EXIT_OK
    assert "No findings" in capsys.readouterr().out


def test_a_failing_server_is_bad_input_not_a_traceback(capsys):
    exit_code = main(["scan", *_cli_source("crash")])

    assert exit_code == EXIT_BAD_INPUT
    assert "mcplint:" in capsys.readouterr().err


def test_a_path_and_a_command_together_is_a_usage_error():
    with pytest.raises(SystemExit):
        main(["scan", "tools.json", "--stdio-command", "anything"])


def test_neither_a_path_nor_a_command_is_a_usage_error():
    with pytest.raises(SystemExit):
        main(["scan"])


def test_a_stray_stdio_arg_is_a_usage_error(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "tools.json", "--stdio-arg", "-y"])

    assert "nothing to attach to" in capsys.readouterr().err


def test_a_stdio_arg_may_start_with_a_dash(capsys):
    # `npx -y some-server` is how nearly every MCP server says to launch it, and
    # the README's own example passes `--stdio-arg -y`. argparse alone reads that
    # `-y` as a new flag rather than as the value, and the scan never starts.
    source = ["--stdio-command", sys.executable, "--stdio-arg", "-u"]
    source += ["--stdio-arg", SERVER, "--stdio-arg", "clean"]

    assert main(["scan", *source]) == EXIT_OK
    assert "No findings" in capsys.readouterr().out


def test_a_trailing_stdio_arg_with_no_value_is_still_a_usage_error():
    with pytest.raises(SystemExit):
        main(["scan", "--stdio-command", sys.executable, "--stdio-arg"])


# --- pin and diff over stdio ------------------------------------------------


def test_pinning_a_live_server_requires_somewhere_to_put_the_baseline():
    # A command line is not a location. Guessing a filename from one would put
    # two different servers in one baseline the first time anybody ran `npx`
    # twice, so the flag is required rather than invented.
    with pytest.raises(SystemExit):
        main(["pin", *_cli_source("clean")])


def test_pin_and_diff_round_trip_against_a_live_server(tmp_path, capsys):
    baseline = tmp_path / "server.mcplint.json"

    assert main(["pin", *_cli_source("clean"), "--baseline", str(baseline)]) == EXIT_OK
    assert baseline.exists()
    capsys.readouterr()

    assert main(["diff", *_cli_source("clean"), "--baseline", str(baseline)]) == EXIT_OK
    assert "No findings" in capsys.readouterr().out


def test_diff_notices_a_live_server_that_changed(tmp_path, capsys):
    baseline = tmp_path / "server.mcplint.json"
    main(["pin", *_cli_source("clean"), "--baseline", str(baseline)])
    capsys.readouterr()

    # Same server, different tools: exactly the shape of a rug pull.
    exit_code = main(["diff", *_cli_source("poisoned"), "--baseline", str(baseline)])

    assert exit_code == EXIT_FINDINGS
    assert "TOOL_ADDED" in capsys.readouterr().out


# --- the server fixture itself ----------------------------------------------


def test_the_fixture_server_is_runnable_on_its_own():
    # It is documented as something you can run by hand to see what the loader
    # sees. If that stops being true the docstring is a lie.
    request = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
    completed = subprocess.run(
        [sys.executable, SERVER, "clean"],
        input=request,
        capture_output=True,
        text=True,
        timeout=PATIENCE,
        check=False,
    )

    assert '"result"' in completed.stdout
