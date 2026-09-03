"""Tests for the description outlier rule.

The load-bearing tests here are the two under "the statistics". They pin down
why the rule measures against the median rather than the mean, so nobody
simplifies that away later and ships a check that quietly never fires.
"""

import statistics
from pathlib import Path

from mcplint.core import LOW, Tool, load_tools_from_json, run_all
from mcplint.rules.description_outliers import (
    MINIMUM_LENGTH,
    MINIMUM_TOOLS,
    MODIFIED_Z_THRESHOLD,
    RULE_ID,
    check_description_outliers,
)
from mcplint.rules.injection import check_injection_phrases

FIXTURES = Path(__file__).parent / "fixtures"


def _server(*lengths):
    """A server whose tool descriptions have exactly the given lengths."""
    return [
        Tool(name=f"tool_{index}", description="x" * length) for index, length in enumerate(lengths)
    ]


# --- the fixture ------------------------------------------------------------


def test_outlier_fixture_flags_the_long_description():
    tools = load_tools_from_json(FIXTURES / "outlier_description.json")

    findings = check_description_outliers(tools)

    assert [finding.tool_name for finding in findings] == ["search_repository"]
    assert findings[0].rule_id == RULE_ID
    assert findings[0].severity == LOW


def test_outlier_fixture_trips_nothing_else():
    # The fixture is a clean server with one bloated tool. If another rule
    # fires on it, the fixture is testing two things and neither one clearly.
    tools = load_tools_from_json(FIXTURES / "outlier_description.json")

    assert {finding.rule_id for finding in run_all(tools)} == {RULE_ID}


def test_the_payload_is_worded_around_the_injection_rule():
    # The whole argument for this rule. The fixture's long description asks the
    # assistant to read credential files and not mention it, in words the
    # phrase list does not contain -- so only its shape gives it away.
    tools = load_tools_from_json(FIXTURES / "outlier_description.json")

    assert check_injection_phrases(tools) == []
    assert check_description_outliers(tools)


def test_clean_fixture_produces_no_findings():
    tools = load_tools_from_json(FIXTURES / "clean_tools.json")

    assert check_description_outliers(tools) == []


# --- the statistics ---------------------------------------------------------


def test_a_mean_based_score_could_not_fire_at_all():
    # An outlier inflates the very deviation it is measured against, so with
    # population statistics over n samples no value can sit further than
    # sqrt(n-1) deviations from the mean however extreme it is. At the minimum
    # server size that ceiling is 2.0 -- below the threshold. A rule built on
    # the mean would look entirely reasonable in review and never once fire.
    lengths = [40] * (MINIMUM_TOOLS - 1) + [50_000]
    ceiling = (len(lengths) - 1) ** 0.5

    mean_based = (lengths[-1] - statistics.fmean(lengths)) / statistics.pstdev(lengths)

    assert mean_based <= ceiling
    assert ceiling < MODIFIED_Z_THRESHOLD
    assert check_description_outliers(_server(*lengths)), "the rule must still fire"


def test_two_outliers_do_not_mask_each_other():
    # Leaving each value out of its own baseline handles one outlier and then
    # fails on two, because each inflates the baseline the other is measured
    # against. Three poisoned tools on one server is not a strange case; it is
    # what shadowing looks like. The median does not have this problem.
    findings = check_description_outliers(_server(40, 40, 40, 40, 40, 40, 4_000, 4_200))

    assert len(findings) == 2


def test_a_server_below_the_minimum_size_is_skipped():
    lengths = [40] * (MINIMUM_TOOLS - 2) + [50_000]

    assert check_description_outliers(_server(*lengths)) == []


def test_identical_neighbours_do_not_divide_by_zero():
    # Every other description the same length means zero spread. That is the
    # clearest possible outlier, not an arithmetic error.
    findings = check_description_outliers(_server(40, 40, 40, 40, 40, 5_000))

    assert len(findings) == 1


def test_a_uniform_server_produces_nothing():
    assert check_description_outliers(_server(*[400] * 8)) == []


# --- the two floors ---------------------------------------------------------


def test_a_short_description_is_not_an_outlier_however_unusual():
    # Ten times the median, but the median is tiny and so is this. Nothing to
    # report: a rule that fires here is a rule that fires on every server.
    lengths = [4] * 7 + [MINIMUM_LENGTH - 1]

    assert check_description_outliers(_server(*lengths)) == []


def test_a_long_description_in_proportion_is_not_an_outlier():
    # Long, but so is everything else on this server. Some tools genuinely need
    # a paragraph, and a server of them is not suspicious.
    lengths = [900] * 7 + [1_100]

    assert check_description_outliers(_server(*lengths)) == []


# --- the finding itself -----------------------------------------------------


def test_the_finding_reports_a_ratio_and_a_length():
    findings = check_description_outliers(_server(40, 40, 40, 40, 40, 400))

    assert "10.0x" in findings[0].message
    assert "400 characters" in findings[0].message


def test_the_evidence_quotes_the_start_without_the_whole_payload():
    tools = _server(40, 40, 40, 40, 40, 4_000)

    snippet = check_description_outliers(tools)[0].evidence_snippet

    assert snippet.endswith("...")
    assert len(snippet) < 200
