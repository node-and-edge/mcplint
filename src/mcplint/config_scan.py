"""Finds the MCP servers already configured on this machine, and reads them.

Why this file exists
--------------------
Every other input to mcplint is a tool list you went and fetched. This one is
the list of servers you already agreed to run, sitting in a config file you
edited once and have not opened since. That file is worth reading on its own,
before any tool description is involved: it is where the launch command lives,
where credentials get pasted, and where a server you installed for one
afternoon stays registered for a year.

Reading it is also the only way to answer "what am I actually running?" without
a checklist. Nobody keeps the checklist.

What this file does *not* do
----------------------------
It never starts anything it finds. Discovery reads JSON off the disk and
returns dataclasses; that is the whole contract. A tool that scanned your
config and then executed every command in it would be a more efficient attack
than most of the ones this project detects, and "I found it in a config file"
is not consent. Running a server requires you to type its command yourself,
after `--stdio-command`.

The checks that read these results live in `rules/config_hygiene.py`, which
takes them as arguments and touches no disk. This split is why "no rule can do
I/O" stays true even though config hygiene needs a file.

Config shapes
-------------
Nearly every client stores the same object under `mcpServers`, keyed by the
name the model sees:

    {"mcpServers": {"files": {"command": "npx", "args": ["-y", "..."]}}}

VS Code spells that key `servers`, and remote servers carry a `url` instead of
a `command`. Both are handled. Anything else is skipped rather than guessed at.
"""

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The key each client stores its servers under. Both are accepted everywhere,
# since a project-local file and a user-level one may disagree.
SERVER_KEYS = ("mcpServers", "servers")

# Config files that live in a project directory rather than a home directory,
# checked relative to wherever mcplint was run.
PROJECT_CONFIGS = (
    ("Claude Code", Path(".mcp.json")),
    ("Cursor", Path(".cursor/mcp.json")),
    ("VS Code", Path(".vscode/mcp.json")),
)


@dataclass
class ConfiguredServer:
    """One server entry, exactly as some client's config file describes it.

    `command` and `url` are the two shapes a server comes in: something this
    machine launches, or something it connects to. Which of the two it is
    changes entirely what is worth checking about it.
    """

    name: str
    client: str
    source: Path
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_remote(self) -> bool:
        """True when connecting to this server means going over a network."""
        return bool(self.url) and not self.command

    @property
    def launch_line(self) -> str:
        """The command line as a human would write it, for showing back."""
        return " ".join([self.command, *self.args]).strip()


def known_config_paths() -> list[tuple[str, Path]]:
    """Where each client keeps its MCP config on this platform.

    Returns every location worth looking at, whether or not it exists -- the
    caller decides what to do about a path that is not there, and a user asking
    why their config was missed deserves to see the list that was checked.
    """
    home = Path.home()
    locations: list[tuple[str, Path]] = []

    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        locations += [
            ("Claude Desktop", appdata / "Claude/claude_desktop_config.json"),
            ("VS Code", appdata / "Code/User/mcp.json"),
        ]
    elif sys.platform == "darwin":
        support = home / "Library/Application Support"
        locations += [
            ("Claude Desktop", support / "Claude/claude_desktop_config.json"),
            ("VS Code", support / "Code/User/mcp.json"),
        ]
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        locations += [
            ("Claude Desktop", config / "Claude/claude_desktop_config.json"),
            ("VS Code", config / "Code/User/mcp.json"),
        ]

    locations += [
        ("Claude Code", home / ".claude.json"),
        ("Cursor", home / ".cursor/mcp.json"),
        ("Windsurf", home / ".codeium/windsurf/mcp_config.json"),
    ]

    working_directory = Path.cwd()
    locations += [(client, working_directory / relative) for client, relative in PROJECT_CONFIGS]

    return locations


def discover_servers(
    paths: list[tuple[str, Path]] | None = None,
) -> tuple[list[ConfiguredServer], list[Path]]:
    """Read every config that exists, and say which ones were readable.

    Returns the servers found and the files they came from. An unreadable or
    malformed config is skipped rather than fatal: one broken file on a machine
    with five configs should not stop you seeing the other four.
    """
    servers: list[ConfiguredServer] = []
    read: list[Path] = []

    for client, path in paths if paths is not None else known_config_paths():
        if not path.is_file():
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue

        read.append(path)
        servers.extend(parse_servers(document, client, path))

    return servers, read


def parse_servers(document: Any, client: str, source: Path) -> list[ConfiguredServer]:
    """Pull server entries out of one already-parsed config document."""
    servers: list[ConfiguredServer] = []
    for entry in _server_objects(document):
        for name, definition in entry.items():
            if isinstance(definition, dict):
                servers.append(_build(name, definition, client, source))
    return servers


def _server_objects(document: Any) -> list[dict[str, Any]]:
    """Every `mcpServers`-shaped object in a config, however deeply filed.

    Claude Code keeps one at the top level and another under each project it
    has seen, so a flat read of the root would miss most of a real config.
    """
    found: list[dict[str, Any]] = []
    if not isinstance(document, dict):
        return found

    for key in SERVER_KEYS:
        candidate = document.get(key)
        if isinstance(candidate, dict):
            found.append(candidate)

    for value in document.get("projects", {}).values() if _has_projects(document) else []:
        found.extend(_server_objects(value))

    return found


def _has_projects(document: dict[str, Any]) -> bool:
    return isinstance(document.get("projects"), dict)


def _build(name: str, definition: dict[str, Any], client: str, source: Path) -> ConfiguredServer:
    """One config entry as a `ConfiguredServer`, normalising the loose bits."""
    return ConfiguredServer(
        name=name,
        client=client,
        source=source,
        command=_text(definition.get("command")),
        args=[_text(argument) for argument in definition.get("args") or []],
        env=_string_map(definition.get("env")),
        url=_text(definition.get("url") or definition.get("serverUrl")),
        headers=_string_map(definition.get("headers")),
    )


def _text(value: Any) -> str:
    """A config value as a string, since these files are edited by hand."""
    return value if isinstance(value, str) else ""


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _text(item) for key, item in value.items()}
