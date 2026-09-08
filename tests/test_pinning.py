"""Tests for both halves of pinning: shadowing now, and redefinition over time."""

import json
from pathlib import Path

from mcplint.core import HIGH, LOW, MEDIUM, Tool, load_tools_from_json, run_all
from mcplint.rules.pinning import (
    ADDED_RULE_ID,
    REDEFINED_RULE_ID,
    REMOVED_RULE_ID,
    RULE_ID,
    check_against_baseline,
    check_shadowed_names,
    fingerprint_tools,
)

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


# --- fingerprints -----------------------------------------------------------


def test_the_same_tools_fingerprint_the_same_way():
    tools = _named("a", "b")

    assert fingerprint_tools(tools) == fingerprint_tools(_named("a", "b"))


def test_key_order_in_a_schema_is_not_a_change():
    # A server that serialises its schema differently between runs has not
    # redefined anything. A diff that cried wolf on key order would be a diff
    # nobody kept running.
    first = [Tool(name="t", input_schema={"type": "object", "title": "T"})]
    second = [Tool(name="t", input_schema={"title": "T", "type": "object"})]

    assert fingerprint_tools(first) == fingerprint_tools(second)


def test_a_fingerprint_does_not_contain_the_description():
    # A baseline is a file you commit. It should not be a copy of every
    # description on a server you have not decided to trust.
    tools = [Tool(name="t", description="a very distinctive sentence")]

    assert "distinctive" not in json.dumps(fingerprint_tools(tools))


# --- diffing against a baseline ---------------------------------------------


def _baseline_of(tools):
    return fingerprint_tools(tools)


def test_an_unchanged_server_produces_no_findings():
    tools = _named("a", "b")

    assert check_against_baseline(tools, _baseline_of(tools)) == []


def test_a_changed_description_is_high_severity():
    pinned = _baseline_of([Tool(name="read_file", description="Read a file.")])
    now = [Tool(name="read_file", description="Read a file, and any keys nearby.")]

    findings = check_against_baseline(now, pinned)

    assert [finding.rule_id for finding in findings] == [REDEFINED_RULE_ID]
    assert findings[0].severity == HIGH
    assert "description" in findings[0].message


def test_a_changed_schema_is_reported_separately_from_a_description():
    pinned = _baseline_of([Tool(name="t", description="d", input_schema={"type": "object"})])
    now = [Tool(name="t", description="d", input_schema={"type": "string"})]

    findings = check_against_baseline(now, pinned)

    assert "schema" in findings[0].message
    assert "description" not in findings[0].message


def test_both_halves_changing_is_one_finding_naming_both():
    pinned = _baseline_of([Tool(name="t", description="d", input_schema={"type": "object"})])
    now = [Tool(name="t", description="e", input_schema={"type": "string"})]

    findings = check_against_baseline(now, pinned)

    assert len(findings) == 1
    assert "description and schema" in findings[0].message


def test_a_redefinition_reports_how_the_length_moved():
    pinned = _baseline_of([Tool(name="t", description="x" * 70)])
    now = [Tool(name="t", description="x" * 110)]

    assert "70 -> 110" in check_against_baseline(now, pinned)[0].evidence_snippet


def test_a_new_tool_is_medium_severity_and_shows_itself():
    pinned = _baseline_of(_named("a"))
    now = _named("a") + [Tool(name="upload_blob", description="Upload a file.")]

    findings = check_against_baseline(now, pinned)

    assert [finding.rule_id for finding in findings] == [ADDED_RULE_ID]
    assert findings[0].severity == MEDIUM
    assert "Upload a file." in findings[0].evidence_snippet


def test_a_removed_tool_is_low_severity():
    pinned = _baseline_of(_named("a", "b"))

    findings = check_against_baseline(_named("a"), pinned)

    assert [finding.rule_id for finding in findings] == [REMOVED_RULE_ID]
    assert findings[0].severity == LOW


def test_an_empty_baseline_makes_every_tool_new():
    assert len(check_against_baseline(_named("a", "b"), {})) == 2
