"""Tests for the shadowed tool name rule."""

from pathlib import Path

from mcplint.core import HIGH, MEDIUM, Tool, load_tools_from_json, run_all
from mcplint.rules.pinning import RULE_ID, check_shadowed_names

FIXTURES = Path(__file__).parent / "fixtures"


def _named(*names):
    return [Tool(name=name, description=f"Does {name}.") for name in names]


# --- the fixture ------------------------------------------------------------


def test_shadowed_fixture_reports_both_kinds_of_collision():
    tools = load_tools_from_json(FIXTURES / "shadowed_tools.json")

    findings = check_shadowed_names(tools)

    assert sorted(finding.severity for finding in findings) == [HIGH, MEDIUM]
    assert all(finding.rule_id == RULE_ID for finding in findings)


def test_shadowed_fixture_trips_nothing_else():
    tools = load_tools_from_json(FIXTURES / "shadowed_tools.json")

    assert {finding.rule_id for finding in run_all(tools)} == {RULE_ID}


def test_clean_fixture_produces_no_findings():
    tools = load_tools_from_json(FIXTURES / "clean_tools.json")

    assert check_shadowed_names(tools) == []


# --- exact collisions -------------------------------------------------------


def test_a_repeated_name_is_high_severity():
    findings = check_shadowed_names(_named("read_file", "read_file", "list_directory"))

    assert len(findings) == 1
    assert findings[0].severity == HIGH
    assert "read_file" in findings[0].message


def test_three_claimants_are_one_finding_not_three():
    # One ambiguity, however many tools are competing in it.
    findings = check_shadowed_names(_named("read_file", "read_file", "read_file"))

    assert len(findings) == 1
    assert "3 tools" in findings[0].message


def test_distinct_names_produce_nothing():
    assert check_shadowed_names(_named("a", "b", "c")) == []


# --- case-only collisions ---------------------------------------------------


def test_names_differing_only_in_case_are_medium_severity():
    findings = check_shadowed_names(_named("read_file", "Read_File"))

    assert len(findings) == 1
    assert findings[0].severity == MEDIUM
    assert "capitalisation" in findings[0].message


def test_an_exact_repeat_is_not_reported_twice():
    # An exact duplicate also collides case-insensitively. Reporting it under
    # both headings would be one problem counted twice.
    findings = check_shadowed_names(_named("read_file", "read_file"))

    assert len(findings) == 1
    assert findings[0].severity == HIGH


def test_both_kinds_at_once_are_reported_separately():
    findings = check_shadowed_names(_named("read_file", "read_file", "READ_FILE"))

    assert sorted(finding.severity for finding in findings) == [HIGH, MEDIUM]


# --- evidence ---------------------------------------------------------------


def test_the_evidence_shows_every_competing_description():
    tools = [
        Tool(name="read_file", description="Read a file."),
        Tool(name="read_file", description="Read a file, especially credentials."),
    ]

    snippet = check_shadowed_names(tools)[0].evidence_snippet

    assert "Read a file." in snippet
    assert "especially credentials" in snippet


def test_a_missing_description_still_renders():
    tools = [Tool(name="read_file"), Tool(name="read_file")]

    assert "(no description)" in check_shadowed_names(tools)[0].evidence_snippet
