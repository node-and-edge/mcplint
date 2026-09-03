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


# --- output formats and thresholds ------------------------------------------

OUTLIER = str(FIXTURES / "outlier_description.json")
POISONED = str(FIXTURES / "poisoned_everything.json")


def test_the_default_threshold_is_medium(capsys):
    # The outlier fixture's only finding is LOW, so a default run reports it
    # and still exits clean. This is the documented contract, asserted here
    # rather than left implied by whichever rule happened to fire.
    exit_code = main(["scan", OUTLIER])

    assert exit_code == EXIT_OK
    assert "DESCRIPTION_OUTLIER" in capsys.readouterr().out


def test_fail_on_low_makes_that_same_run_fail():
    assert main(["scan", OUTLIER, "--fail-on", "low"]) == EXIT_FINDINGS


def test_fail_on_high_ignores_a_medium_finding():
    assert main(["scan", str(FIXTURES / "permissive_schema.json"), "--fail-on", "high"]) == EXIT_OK


def test_fail_on_never_reports_everything_and_still_exits_zero(capsys):
    exit_code = main(["scan", POISONED, "--fail-on", "never"])

    assert exit_code == EXIT_OK
    assert "INJECTION_PHRASE" in capsys.readouterr().out


def test_quiet_prints_nothing_at_all(capsys):
    exit_code = main(["scan", POISONED, "--quiet"])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert exit_code == EXIT_FINDINGS, "quiet changes what is printed, not what is found"


def test_quiet_does_not_change_the_exit_code():
    assert main(["scan", POISONED]) == main(["scan", POISONED, "--quiet"])
    assert main(["scan", str(FIXTURES / "clean_tools.json"), "--quiet"]) == EXIT_OK


def test_the_format_does_not_change_the_exit_code():
    # A CI job that switches to SARIF for nicer annotations must not quietly
    # stop failing at the same time.
    codes = {main(["scan", POISONED, "--format", fmt]) for fmt in ("text", "json", "sarif")}

    assert codes == {EXIT_FINDINGS}


def test_json_output_parses(capsys):
    main(["scan", POISONED, "--format", "json"])

    document = json.loads(capsys.readouterr().out)

    assert document["counts"]["high"] == 4
    assert len(document["findings"]) == 6


def test_sarif_output_parses(capsys):
    main(["scan", POISONED, "--format", "sarif"])

    document = json.loads(capsys.readouterr().out)

    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"]


def test_sarif_records_the_file_it_scanned(capsys):
    main(["scan", POISONED, "--format", "sarif"])

    document = json.loads(capsys.readouterr().out)
    location = document["runs"][0]["results"][0]["locations"][0]

    assert location["physicalLocation"]["artifactLocation"]["uri"] == POISONED


def test_quiet_pin_says_nothing(tmp_path, capsys):
    path = _server_file(tmp_path, ONE_TOOL)

    assert main(["pin", str(path), "--quiet"]) == EXIT_OK
    assert capsys.readouterr().out == ""
    assert (tmp_path / "tools.mcplint.json").exists()


def test_pin_offers_no_format_flag_because_it_reports_no_findings():
    with pytest.raises(SystemExit):
        main(["pin", "tools.json", "--format", "json"])


# --- scanning several files at once -----------------------------------------

CLEAN = str(FIXTURES / "clean_tools.json")
INJECTION = str(FIXTURES / "poisoned_injection.json")


def test_several_files_are_scanned_in_one_run(capsys):
    # What a pre-commit hook does: hand over every staged file that matched and
    # expect the tool to cope.
    exit_code = main(["scan", CLEAN, INJECTION])

    assert exit_code == EXIT_FINDINGS
    assert "INJECTION_PHRASE" in capsys.readouterr().out


def test_findings_say_which_file_they_came_from(capsys):
    main(["scan", CLEAN, INJECTION])

    assert INJECTION in capsys.readouterr().out


def test_a_single_file_does_not_get_a_redundant_filename(capsys):
    # One file scanned is the common case, and repeating its name against every
    # finding would be noise.
    main(["scan", INJECTION])

    assert f"({INJECTION})" not in capsys.readouterr().out


def test_the_worst_file_decides_the_exit_code():
    assert main(["scan", CLEAN, CLEAN]) == EXIT_OK
    assert main(["scan", CLEAN, INJECTION]) == EXIT_FINDINGS


def test_an_unreadable_file_among_readable_ones_is_still_bad_input(capsys):
    exit_code = main(["scan", CLEAN, str(FIXTURES / "absent.json")])

    assert exit_code == EXIT_BAD_INPUT
    assert "could not read" in capsys.readouterr().err


def test_same_named_tools_in_different_files_are_reported_separately(capsys):
    # Both files define `read_file`. Merging them under one heading would put
    # a finding in the wrong file, which over forty staged files is the
    # difference between a report and a puzzle.
    main(["scan", INJECTION, str(FIXTURES / "shadowed_tools.json")])

    assert capsys.readouterr().out.count("tool: read_file") == 2


def test_json_output_tags_each_finding_with_its_file(capsys):
    main(["scan", CLEAN, INJECTION, "--format", "json"])

    document = json.loads(capsys.readouterr().out)

    assert {finding["source"] for finding in document["findings"]} == {INJECTION}


def test_pin_refuses_more_than_one_tool_list():
    # A baseline describes one server. Quietly pinning four of them into one
    # file would be worse than refusing.
    with pytest.raises(SystemExit):
        main(["pin", CLEAN, INJECTION])
