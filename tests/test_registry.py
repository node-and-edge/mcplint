"""Tests that every rule is actually wired into a scan.

A rule can be written, fixtured and unit-tested to a green tick and still not
run, because `run_all` is a hand-written tuple and forgetting a line in it
breaks nothing loudly. These tests are the thing that notices.

`poisoned_everything.json` is one server carrying one payload per rule. It is
also the honest answer to "what does an actual attack look like" -- worth
reading before the code.
"""

from pathlib import Path

from mcplint.core import HIGH, LOW, MEDIUM, load_tools_from_json, run_all
from mcplint.report import RULE_DESCRIPTIONS
from mcplint.rules import (
    config_hygiene,
    description_outliers,
    injection,
    pinning,
    schema_permissiveness,
)
from mcplint.rules import unicode_anomaly as unicode

FIXTURES = Path(__file__).parent / "fixtures"

# Every rule identifier a scan can produce. `pin`/`diff` add three more, but
# those need a baseline and so are not part of a scan.
EVERY_SCAN_RULE_ID = {
    injection.RULE_ID,
    unicode.INVISIBLE_RULE_ID,
    unicode.BIDI_RULE_ID,
    unicode.MIXED_SCRIPT_RULE_ID,
    schema_permissiveness.RULE_ID,
    description_outliers.RULE_ID,
    pinning.RULE_ID,
}

# Every identifier the tool can emit anywhere, read off the rule modules rather
# than typed out again, so this cannot agree with a stale copy of itself.
EVERY_RULE_ID = EVERY_SCAN_RULE_ID | {
    pinning.ADDED_RULE_ID,
    pinning.REMOVED_RULE_ID,
    pinning.REDEFINED_RULE_ID,
    config_hygiene.SHELL_LAUNCH_RULE_ID,
    config_hygiene.PLAINTEXT_SECRET_RULE_ID,
    config_hygiene.INSECURE_TRANSPORT_RULE_ID,
    config_hygiene.NO_AUTH_RULE_ID,
}


def _scan(name):
    return run_all(load_tools_from_json(FIXTURES / name))


def test_every_rule_fires_on_the_combined_fixture():
    # The completion criterion for the rule set: one server, one payload per
    # rule, every rule reporting. A rule missing from `run_all` fails here and
    # nowhere else.
    found = {finding.rule_id for finding in _scan("poisoned_everything.json")}

    assert found == {
        injection.RULE_ID,
        unicode.INVISIBLE_RULE_ID,
        schema_permissiveness.RULE_ID,
        description_outliers.RULE_ID,
        pinning.RULE_ID,
    }


def test_the_clean_fixture_stays_clean_under_every_rule():
    # The shared negative control. Every rule added from here on has to keep
    # this passing, which is what stops the tool crying wolf on a good server.
    assert _scan("clean_tools.json") == []


def test_each_single_purpose_fixture_trips_only_its_own_rule():
    expected = {
        "poisoned_injection.json": {injection.RULE_ID},
        "poisoned_unicode.json": {
            unicode.INVISIBLE_RULE_ID,
            unicode.BIDI_RULE_ID,
            unicode.MIXED_SCRIPT_RULE_ID,
        },
        "permissive_schema.json": {schema_permissiveness.RULE_ID},
        "outlier_description.json": {description_outliers.RULE_ID},
        "shadowed_tools.json": {pinning.RULE_ID},
    }

    for fixture, rule_ids in expected.items():
        assert {finding.rule_id for finding in _scan(fixture)} == rule_ids, fixture


def test_every_finding_carries_evidence_and_a_remedy():
    # A finding the user cannot verify by eye is one they have to take on
    # faith, and taking things on faith is what this project exists to avoid.
    for finding in _scan("poisoned_everything.json"):
        assert finding.evidence_snippet, finding.rule_id
        assert finding.remediation, finding.rule_id


def test_every_severity_is_one_the_cli_can_rank():
    for finding in _scan("poisoned_everything.json"):
        assert finding.severity in (HIGH, MEDIUM, LOW)


def test_no_rule_reports_an_identifier_outside_the_documented_set():
    for name in ("poisoned_everything.json", "poisoned_unicode.json", "shadowed_tools.json"):
        for finding in _scan(name):
            assert finding.rule_id in EVERY_SCAN_RULE_ID, finding.rule_id


def test_every_rule_id_has_a_description_for_sarif():
    # The other half of the check in `test_report.py`. That one asks whether
    # each name in the table is real; this asks whether the table is missing
    # one the code can actually produce -- which is the direction that goes
    # wrong, because adding a rule and forgetting the table breaks nothing.
    missing = EVERY_RULE_ID - set(RULE_DESCRIPTIONS)

    assert not missing, f"rules with no SARIF description: {sorted(missing)}"


def test_the_description_table_has_no_entries_for_rules_that_do_not_exist():
    stale = set(RULE_DESCRIPTIONS) - EVERY_RULE_ID

    assert not stale, f"descriptions for rules that no longer exist: {sorted(stale)}"
