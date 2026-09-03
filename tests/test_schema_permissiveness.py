"""Tests for the schema permissiveness rule.

Half of these are negative cases, deliberately. This is the rule most likely to
cry wolf on an honest server, and a permissiveness check that flags every
string parameter is a check people turn off.
"""

from pathlib import Path

from mcplint.core import MEDIUM, Tool, load_tools_from_json
from mcplint.rules.schema_permissiveness import (
    CONSTRAINT_KEYWORDS,
    RULE_ID,
    check_schema_permissiveness,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _tool(schema):
    return [Tool(name="t", description="", input_schema=schema)]


def _string_parameter(name, **constraints):
    return {"type": "object", "properties": {name: {"type": "string", **constraints}}}


def _flagged_paths(findings):
    return {finding.message.split('"')[1] for finding in findings}


# --- the fixtures -----------------------------------------------------------


def test_permissive_fixture_flags_exactly_the_dangerous_parameters():
    tools = load_tools_from_json(FIXTURES / "permissive_schema.json")

    findings = check_schema_permissiveness(tools)

    assert _flagged_paths(findings) == {
        "command",
        "options.file_path",
        "targets.targetUrl",
    }
    assert all(finding.rule_id == RULE_ID for finding in findings)
    assert all(finding.severity == MEDIUM for finding in findings)


def test_clean_fixture_produces_no_findings():
    # The clean fixture's `path` and `url` parameters are bounded, which is the
    # whole point of it: this is what a server that thought about its schema
    # looks like.
    tools = load_tools_from_json(FIXTURES / "clean_tools.json")

    assert check_schema_permissiveness(tools) == []


# --- what counts as constrained ---------------------------------------------


def test_a_bare_dangerous_parameter_is_flagged():
    findings = check_schema_permissiveness(_tool(_string_parameter("command")))

    assert len(findings) == 1
    assert findings[0].rule_id == RULE_ID


def test_any_single_constraint_clears_it():
    examples = {
        "enum": ["ls", "pwd"],
        "const": "ls",
        "pattern": "^ls$",
        "maxLength": 16,
        "format": "uri",
    }
    assert set(examples) == set(CONSTRAINT_KEYWORDS), "test drifted from the rule"

    for keyword, value in examples.items():
        schema = _string_parameter("command", **{keyword: value})

        assert check_schema_permissiveness(_tool(schema)) == [], f"{keyword} should bound it"


def test_a_non_string_parameter_is_not_flagged():
    schema = {"type": "object", "properties": {"command": {"type": "integer"}}}

    assert check_schema_permissiveness(_tool(schema)) == []


def test_a_nullable_string_is_still_a_string():
    schema = {"type": "object", "properties": {"path": {"type": ["string", "null"]}}}

    assert len(check_schema_permissiveness(_tool(schema))) == 1


def test_an_empty_schema_is_not_a_finding():
    # Nothing to constrain is not the same as something left unconstrained.
    assert check_schema_permissiveness(_tool({})) == []


# --- which names count as dangerous -----------------------------------------


def test_a_harmless_free_text_parameter_is_left_alone():
    # The rule that flags `nickname` is the rule nobody keeps enabled.
    for name in ("nickname", "message", "title", "comment", "body"):
        assert check_schema_permissiveness(_tool(_string_parameter(name))) == [], name


def test_names_are_matched_by_token_not_by_spelling():
    for name in ("file_path", "filePath", "target_url", "targetUrl", "sql-query", "dest.path"):
        findings = check_schema_permissiveness(_tool(_string_parameter(name)))

        assert len(findings) == 1, f"{name} should be recognised"


def test_the_finding_names_what_the_parameter_reaches():
    findings = check_schema_permissiveness(_tool(_string_parameter("command")))

    assert "shell command" in findings[0].message


# --- walking the schema -----------------------------------------------------


def test_nested_objects_are_walked():
    schema = {
        "type": "object",
        "properties": {
            "outer": {
                "type": "object",
                "properties": {"inner": {"type": "object", "properties": _deep_command()}},
            }
        },
    }

    findings = check_schema_permissiveness(_tool(schema))

    assert _flagged_paths(findings) == {"outer.inner.cmd"}


def _deep_command():
    return {"cmd": {"type": "string"}}


def test_array_items_are_walked():
    schema = {
        "type": "object",
        "properties": {
            "steps": {"type": "array", "items": {"type": "object", "properties": _deep_command()}}
        },
    }

    assert _flagged_paths(check_schema_permissiveness(_tool(schema))) == {"steps.cmd"}


def test_branches_of_a_union_are_walked():
    schema = {
        "type": "object",
        "properties": {
            "input": {
                "anyOf": [
                    {"type": "object", "properties": {"safe": {"type": "string"}}},
                    {"type": "object", "properties": _deep_command()},
                ]
            }
        },
    }

    assert _flagged_paths(check_schema_permissiveness(_tool(schema))) == {"input.cmd"}


def test_a_pathologically_deep_schema_terminates():
    schema = {"type": "string"}
    for _ in range(200):
        schema = {"type": "object", "properties": {"nest": schema}}

    check_schema_permissiveness(_tool(schema))


# --- evidence ---------------------------------------------------------------


def test_the_finding_carries_the_path_and_the_schema_keys():
    schema = {
        "type": "object",
        "properties": {"options": {"type": "object", "properties": _deep_command()}},
    }

    finding = check_schema_permissiveness(_tool(schema))[0]

    assert "options.cmd" in finding.message
    assert "options.cmd" in finding.remediation
    assert finding.evidence_snippet
