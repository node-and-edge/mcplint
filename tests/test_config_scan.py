"""Tests for config discovery and parsing.

Every test here points discovery at a temporary directory. Nothing reads the
machine's real config, and nothing starts anything it finds -- which is also
the property the last test in this file asserts.
"""

import json
from pathlib import Path

from mcplint.config_scan import (
    ConfiguredServer,
    discover_servers,
    known_config_paths,
    parse_servers,
)


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


LOCAL_SERVER = {"command": "npx", "args": ["-y", "server-filesystem", "/srv"]}
REMOTE_SERVER = {"url": "https://mcp.example.com/sse"}


# --- parsing ----------------------------------------------------------------


def test_a_standard_config_yields_its_servers():
    document = {"mcpServers": {"files": LOCAL_SERVER}}

    servers = parse_servers(document, "Claude Desktop", Path("config.json"))

    assert len(servers) == 1
    assert servers[0].name == "files"
    assert servers[0].command == "npx"
    assert servers[0].args == ["-y", "server-filesystem", "/srv"]
    assert servers[0].client == "Claude Desktop"


def test_the_vs_code_spelling_is_understood_too():
    servers = parse_servers({"servers": {"files": LOCAL_SERVER}}, "VS Code", Path("mcp.json"))

    assert [server.name for server in servers] == ["files"]


def test_servers_nested_under_projects_are_found():
    # Claude Code files a server list per project it has seen. A flat read of
    # the root would miss most of a real config.
    document = {
        "mcpServers": {"global": LOCAL_SERVER},
        "projects": {
            "/home/me/api": {"mcpServers": {"api-tools": LOCAL_SERVER}},
            "/home/me/web": {"mcpServers": {"web-tools": REMOTE_SERVER}},
        },
    }

    servers = parse_servers(document, "Claude Code", Path(".claude.json"))

    assert {server.name for server in servers} == {"global", "api-tools", "web-tools"}


def test_a_remote_server_is_distinguished_from_a_local_one():
    servers = parse_servers(
        {"mcpServers": {"local": LOCAL_SERVER, "remote": REMOTE_SERVER}},
        "Cursor",
        Path("mcp.json"),
    )
    by_name = {server.name: server for server in servers}

    assert by_name["remote"].is_remote
    assert not by_name["local"].is_remote


def test_the_launch_line_reads_the_way_a_person_would_write_it():
    server = parse_servers({"mcpServers": {"files": LOCAL_SERVER}}, "c", Path("f"))[0]

    assert server.launch_line == "npx -y server-filesystem /srv"


def test_environment_and_headers_come_through_as_strings():
    document = {
        "mcpServers": {
            "one": {"command": "run", "env": {"TOKEN": "abc", "PORT": 8080}},
            "two": {"url": "https://x", "headers": {"Authorization": "Bearer y"}},
        }
    }

    servers = {s.name: s for s in parse_servers(document, "c", Path("f"))}

    assert servers["one"].env["TOKEN"] == "abc"
    assert servers["one"].env["PORT"] == ""
    assert servers["two"].headers["Authorization"] == "Bearer y"


def test_nonsense_is_skipped_rather_than_guessed_at():
    for document in ([], "text", 7, None, {"mcpServers": "not an object"}):
        assert parse_servers(document, "c", Path("f")) == []


def test_a_server_entry_that_is_not_an_object_is_skipped():
    document = {"mcpServers": {"broken": "npx server", "fine": LOCAL_SERVER}}

    assert [s.name for s in parse_servers(document, "c", Path("f"))] == ["fine"]


# --- discovery --------------------------------------------------------------


def test_discovery_reads_every_config_that_exists(tmp_path):
    first = _write(tmp_path / "a.json", {"mcpServers": {"one": LOCAL_SERVER}})
    second = _write(tmp_path / "b.json", {"mcpServers": {"two": REMOTE_SERVER}})

    servers, read = discover_servers([("A", first), ("B", second)])

    assert {server.name for server in servers} == {"one", "two"}
    assert read == [first, second]


def test_a_config_that_is_not_there_is_not_an_error(tmp_path):
    servers, read = discover_servers([("A", tmp_path / "absent.json")])

    assert servers == []
    assert read == []


def test_one_broken_config_does_not_hide_the_others(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{ this is not json", encoding="utf-8")
    good = _write(tmp_path / "good.json", {"mcpServers": {"fine": LOCAL_SERVER}})

    servers, read = discover_servers([("A", broken), ("B", good)])

    assert [server.name for server in servers] == ["fine"]
    assert read == [good]


def test_each_server_remembers_where_it_came_from(tmp_path):
    path = _write(tmp_path / "cursor.json", {"mcpServers": {"one": LOCAL_SERVER}})

    servers, _ = discover_servers([("Cursor", path)])

    assert servers[0].source == path
    assert servers[0].client == "Cursor"


# --- the known locations ----------------------------------------------------


def test_the_known_locations_are_absolute_and_named():
    for client, path in known_config_paths():
        assert client, "every location needs a client name to report"
        assert path.is_absolute(), path


def test_the_usual_clients_are_all_looked_for():
    clients = {client for client, _ in known_config_paths()}

    assert {"Claude Desktop", "Claude Code", "Cursor", "VS Code", "Windsurf"} <= clients


def test_project_local_configs_are_looked_for_too():
    paths = [str(path) for _, path in known_config_paths()]

    assert any(path.endswith(".mcp.json") for path in paths)
    assert any(path.replace("\\", "/").endswith(".cursor/mcp.json") for path in paths)


# --- the safety property ----------------------------------------------------


def test_discovery_never_starts_anything_it_finds(tmp_path, monkeypatch):
    # The property that matters most in this file. A tool that read your config
    # and then ran every command in it would be a more efficient attack than
    # most of the ones this project detects. "I found it in a config file" is
    # not consent.
    import subprocess

    def refuse(*args, **kwargs):
        raise AssertionError("discovery must never spawn a process")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)

    path = _write(
        tmp_path / "config.json",
        {"mcpServers": {"dangerous": {"command": "rm", "args": ["-rf", "/"]}}},
    )
    servers, _ = discover_servers([("A", path)])

    assert servers[0].command == "rm"
    assert isinstance(servers[0], ConfiguredServer)
