"""Tests for the output formats.

The text renderer's tests are about what a person can see: an invisible
character must not print as nothing, and a server must not be labelled a tool.
The SARIF tests are about shape, since the consumer is a machine with opinions.
"""

import json

import pytest

from mcplint.core import HIGH, LOW, MEDIUM, Finding
from mcplint.report import (
    RULE_DESCRIPTIONS,
    SARIF_LEVELS,
    SARIF_VERSION,
    render_json,
    render_sarif,
    render_text,
    visible,
)

ZERO_WIDTH_SPACE = "\u200b"


def _finding(**overrides):
    fields = {
        "rule_id": "INJECTION_PHRASE",
        "severity": HIGH,
        "tool_name": "read_file",
        "message": "description contains an instruction",
        "evidence_snippet": "...ignore previous instructions...",
        "remediation": "Do not connect this server.",
    }
    fields.update(overrides)
    return Finding(**fields)


# --- text -------------------------------------------------------------------


def test_no_findings_says_so_rather_than_printing_nothing():
    assert render_text([], 12) == "No findings across 12 tools."


def test_findings_are_grouped_under_their_subject():
    text = render_text([_finding(), _finding(rule_id="SHADOWED_TOOL_NAME")], 3)

    assert text.count("tool: read_file") == 1


def test_a_server_finding_is_labelled_a_server():
    finding = _finding(tool_name="files", subject_kind="server")

    assert "server: files" in render_text([finding], 1, "servers")


def test_the_summary_counts_every_severity():
    findings = [_finding(), _finding(severity=MEDIUM), _finding(severity=LOW)]

    assert "3 findings across 9 tools. 1 high, 1 medium, 1 low." in render_text(findings, 9)


def test_one_finding_is_singular():
    assert "1 finding across" in render_text([_finding()], 4)


def test_an_invisible_character_in_a_name_is_shown_as_its_codepoint():
    # Printing the name as sent would let a poisoned name look clean in the
    # output of the tool reporting that it is not.
    finding = _finding(tool_name=f"read{ZERO_WIDTH_SPACE}_file")

    text = render_text([finding], 1)

    assert "<U+200B>" in text
    assert ZERO_WIDTH_SPACE not in text


def test_visible_leaves_ordinary_text_alone():
    assert visible("read_file") == "read_file"


def test_evidence_is_printed_when_there_is_any():
    assert "ignore previous instructions" in render_text([_finding()], 1)
    assert "\n" in render_text([_finding(evidence_snippet="")], 1)


# --- SARIF ------------------------------------------------------------------


def _sarif(findings, source="tools.json"):
    return json.loads(render_sarif(findings, source))


def test_sarif_is_valid_json_with_the_expected_envelope():
    document = _sarif([_finding()])

    assert document["version"] == SARIF_VERSION
    assert document["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(document["runs"]) == 1
    assert document["runs"][0]["tool"]["driver"]["name"] == "mcplint"


def test_every_finding_becomes_one_result():
    findings = [_finding(), _finding(severity=MEDIUM), _finding(severity=LOW)]

    assert len(_sarif(findings)["runs"][0]["results"]) == 3


def test_severities_map_onto_the_three_sarif_levels():
    findings = [_finding(severity=level) for level in (HIGH, MEDIUM, LOW)]

    levels = [result["level"] for result in _sarif(findings)["runs"][0]["results"]]

    assert levels == ["error", "warning", "note"]
    assert set(SARIF_LEVELS.values()) == {"error", "warning", "note"}


def test_each_rule_that_reported_gets_exactly_one_descriptor():
    findings = [_finding(), _finding(), _finding(rule_id="PERMISSIVE_SCHEMA", severity=MEDIUM)]

    rules = _sarif(findings)["runs"][0]["tool"]["driver"]["rules"]

    assert [rule["id"] for rule in rules] == ["INJECTION_PHRASE", "PERMISSIVE_SCHEMA"]


def test_a_descriptor_takes_the_worst_level_that_rule_reported():
    findings = [_finding(severity=LOW), _finding(severity=HIGH)]

    rule = _sarif(findings)["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["defaultConfiguration"]["level"] == "error"


def test_results_carry_a_location_naming_the_source_and_the_subject():
    location = _sarif([_finding()], "servers/tools.json")["runs"][0]["results"][0]["locations"][0]

    assert location["physicalLocation"]["artifactLocation"]["uri"] == "servers/tools.json"
    assert location["logicalLocations"][0]["name"] == "read_file"


def test_the_message_carries_evidence_and_remedy():
    # A code scanning comment shows the message and little else, so anything
    # left only in `properties` is invisible to the person reading it.
    message = _sarif([_finding()])["runs"][0]["results"][0]["message"]["text"]

    assert "ignore previous instructions" in message
    assert "Do not connect this server." in message


def test_no_findings_still_produces_a_valid_document():
    document = _sarif([])

    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_is_ascii_safe():
    # A Cyrillic tool name has to survive being written to a file by a CI job
    # whose encoding nobody chose deliberately.
    output = render_sarif([_finding(tool_name="fetch_ur\u043el")], "tools.json")

    assert output.isascii()
    assert "\\u043e" in output


# --- the descriptor table ---------------------------------------------------


@pytest.mark.parametrize(
    "rule_id",
    [
        "INJECTION_PHRASE",
        "UNICODE_INVISIBLE",
        "UNICODE_BIDI",
        "UNICODE_MIXED_SCRIPT",
        "PERMISSIVE_SCHEMA",
        "DESCRIPTION_OUTLIER",
        "SHADOWED_TOOL_NAME",
        "TOOL_ADDED",
        "TOOL_REMOVED",
        "TOOL_REDEFINED",
        "CONFIG_SHELL_LAUNCH",
        "CONFIG_PLAINTEXT_SECRET",
        "CONFIG_INSECURE_TRANSPORT",
        "CONFIG_NO_AUTH",
    ],
)
def test_every_rule_the_tool_can_emit_has_a_description(rule_id):
    # A table of descriptions goes stale the moment somebody adds a rule and
    # forgets it. `test_registry.py` checks the other direction -- that this
    # list is not missing a rule the code can actually produce.
    assert rule_id in RULE_DESCRIPTIONS
    assert RULE_DESCRIPTIONS[rule_id].endswith("."), rule_id


# --- JSON -------------------------------------------------------------------


def _as_json(findings, count=3, subject="tools"):
    return json.loads(render_json(findings, count, subject))


def test_json_carries_every_field_of_every_finding():
    document = _as_json([_finding()])

    assert document["findings"] == [
        {
            "rule_id": "INJECTION_PHRASE",
            "severity": HIGH,
            "subject": "read_file",
            "subject_kind": "tool",
            "message": "description contains an instruction",
            "evidence": "...ignore previous instructions...",
            "remediation": "Do not connect this server.",
        }
    ]


def test_json_carries_the_counts_from_the_summary_line():
    findings = [_finding(), _finding(), _finding(severity=LOW)]

    document = _as_json(findings, count=9)

    assert document["counts"] == {"high": 2, "medium": 0, "low": 1}
    assert document["subject_count"] == 9
    assert document["subject"] == "tools"


def test_json_with_no_findings_is_still_a_document():
    document = _as_json([])

    assert document["findings"] == []
    assert document["counts"] == {"high": 0, "medium": 0, "low": 0}


def test_json_is_ascii_safe_like_sarif():
    output = render_json([_finding(tool_name="fetch_ur\u043el")], 1)

    assert output.isascii()


def test_json_is_not_sarif_shaped():
    # These are for different readers. Bending one into the other's shape would
    # make both worse, and SARIF is not a pleasant thing to parse in a shell
    # script on a Tuesday.
    assert "runs" not in _as_json([_finding()])
