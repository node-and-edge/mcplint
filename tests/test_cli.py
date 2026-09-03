"""Tests for the command line surface: argument parsing and exit codes.

The exit-code contract is the part of this tool other software depends on, so
it is asserted here explicitly rather than left implied by a rule test:
0 for a clean run, 1 for a finding at or above the fail threshold, 2 when the
input could not be read at all.
"""

import json
from pathlib import Path

import pytest

from mcplint.cli import EXIT_BAD_INPUT, EXIT_FINDINGS, EXIT_OK, main

FIXTURES = Path(__file__).parent / "fixtures"


# --- scan -------------------------------------------------------------------


def test_clean_scan_exits_zero(capsys):
    exit_code = main(["scan", str(FIXTURES / "clean_tools.json")])

    assert exit_code == EXIT_OK
    assert "No findings" in capsys.readouterr().out


def test_poisoned_scan_exits_nonzero(capsys):
    exit_code = main(["scan", str(FIXTURES / "poisoned_injection.json")])

    assert exit_code == EXIT_FINDINGS
    assert "INJECTION_PHRASE" in capsys.readouterr().out


def test_missing_file_exits_two(capsys):
    exit_code = main(["scan", str(FIXTURES / "does_not_exist.json")])

    assert exit_code == EXIT_BAD_INPUT
    assert "could not read" in capsys.readouterr().err


def test_no_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit):
        main([])


# --- pin and diff -----------------------------------------------------------


def _server_file(directory, tools):
    path = directory / "tools.json"
    path.write_text(json.dumps({"tools": tools}), encoding="utf-8")
    return path


ONE_TOOL = [{"name": "read_file", "description": "Read a file.", "inputSchema": {}}]


def test_pin_writes_a_baseline_beside_the_tool_list(tmp_path, capsys):
    path = _server_file(tmp_path, ONE_TOOL)

    exit_code = main(["pin", str(path)])

    assert exit_code == EXIT_OK
    assert (tmp_path / "tools.mcplint.json").exists()
    assert "Pinned 1 tool" in capsys.readouterr().out


def test_diff_against_an_unchanged_server_exits_zero(tmp_path, capsys):
    path = _server_file(tmp_path, ONE_TOOL)
    main(["pin", str(path)])

    exit_code = main(["diff", str(path)])

    assert exit_code == EXIT_OK
    assert "No findings" in capsys.readouterr().out


def test_diff_reports_a_redefinition_and_exits_nonzero(tmp_path, capsys):
    path = _server_file(tmp_path, ONE_TOOL)
    main(["pin", str(path)])
    _server_file(tmp_path, [{**ONE_TOOL[0], "description": "Read a file, and any keys."}])

    exit_code = main(["diff", str(path)])

    assert exit_code == EXIT_FINDINGS
    assert "TOOL_REDEFINED" in capsys.readouterr().out


def test_the_baseline_location_can_be_overridden(tmp_path):
    path = _server_file(tmp_path, ONE_TOOL)
    elsewhere = tmp_path / "nested" / "pinned.json"
    elsewhere.parent.mkdir()

    assert main(["pin", str(path), "--baseline", str(elsewhere)]) == EXIT_OK
    assert elsewhere.exists()
    assert not (tmp_path / "tools.mcplint.json").exists()
    assert main(["diff", str(path), "--baseline", str(elsewhere)]) == EXIT_OK


def test_diff_without_a_baseline_is_bad_input(tmp_path, capsys):
    path = _server_file(tmp_path, ONE_TOOL)

    exit_code = main(["diff", str(path)])

    assert exit_code == EXIT_BAD_INPUT
    assert "could not read baseline" in capsys.readouterr().err


def test_an_unreadable_baseline_version_fails_loudly(tmp_path, capsys):
    # The failure that matters most. A rug-pull check which quietly compares
    # nothing still exits zero, and an exit code you cannot trust is worse than
    # having no check at all -- so a baseline this build cannot read is an
    # error, never an empty comparison.
    path = _server_file(tmp_path, ONE_TOOL)
    main(["pin", str(path)])
    baseline = tmp_path / "tools.mcplint.json"
    document = json.loads(baseline.read_text(encoding="utf-8"))
    document["version"] = 99
    baseline.write_text(json.dumps(document), encoding="utf-8")

    exit_code = main(["diff", str(path)])

    assert exit_code == EXIT_BAD_INPUT
    assert "version" in capsys.readouterr().err


def test_a_corrupt_baseline_is_bad_input(tmp_path):
    path = _server_file(tmp_path, ONE_TOOL)
    (tmp_path / "tools.mcplint.json").write_text("{not json", encoding="utf-8")

    assert main(["diff", str(path)]) == EXIT_BAD_INPUT
