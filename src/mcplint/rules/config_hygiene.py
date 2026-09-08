"""Flags dangerous ways of *starting* a server, before any tool is involved.

Why this rule exists
--------------------
Every other rule in this directory reads what a server said. This one reads
what you agreed to run, which is a question you answered once, months ago, in
a JSON file you have not opened since.

That file is a better target than any tool description. A poisoned description
has to talk a model into doing something; a poisoned launch command just runs.
And nothing about a config file resists edits: it is plain JSON in a
predictable location, writable by anything running as you, and read at startup
without a prompt. If an attacker can reach it, the tool-poisoning rules further
up this directory are already too late to matter.

Four things worth knowing about a server before you connect to it:

*It goes through a shell.* `"command": "bash", "args": ["-c", "..."]` turns a
launch line into an arbitrary script, and `curl ... | sh` inside one turns it
into an arbitrary script somebody else writes. There is no MCP server that
needs this. A legitimate one names its binary.

*Its credentials are sitting in the file.* Config files get committed,
screen-shared, pasted into issues and synced between machines. A token written
literally into one has a much larger blast radius than its owner expects, and
every client supports referencing an environment variable instead.

*It is reached over plain HTTP.* Tool descriptions and whatever they carry
cross the network in clear, and anyone on the path can rewrite them -- which
makes every other rule in this project unenforceable, since what you scanned is
not necessarily what arrives.

*It is remote with no credential at all.* Sometimes fine, sometimes a server
someone else can also talk to. Scored low, because it is a question rather than
an accusation.

This rule takes already-parsed config entries and touches no disk, which is why
`config_scan.py` exists separately. That keeps "no rule can do I/O" true even
for the check that is fundamentally about a file.
"""

from urllib.parse import urlsplit

from mcplint.config_scan import ConfiguredServer
from mcplint.core import HIGH, LOW, MEDIUM, Finding

SHELL_LAUNCH_RULE_ID = "CONFIG_SHELL_LAUNCH"
PLAINTEXT_SECRET_RULE_ID = "CONFIG_PLAINTEXT_SECRET"
INSECURE_TRANSPORT_RULE_ID = "CONFIG_INSECURE_TRANSPORT"
NO_AUTH_RULE_ID = "CONFIG_NO_AUTH"

# Interpreters that take a script on the command line. Compared against the
# bare program name, so an absolute path to one still matches.
SHELL_PROGRAMS = frozenset(
    {"bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
)

# The flags that turn one of those into "run this string".
SCRIPT_FLAGS = frozenset({"-c", "/c", "/k", "-command", "-encodedcommand", "-e"})

# Substrings that mean the launch line fetches its own code, or evaluates text
# as code. Either one makes the command you reviewed not the command that runs.
FETCH_AND_RUN_MARKERS = ("| sh", "|sh", "| bash", "|bash", "iex ", "eval ", "eval(")

# Environment and header names whose values are worth not writing down.
SECRET_NAME_MARKERS = ("token", "key", "secret", "password", "passwd", "credential", "auth")

# A value shorter than this is a setting, not a credential.
SECRET_MINIMUM_LENGTH = 12

# Header names that count as having authenticated the connection.
AUTH_HEADER_MARKERS = ("authorization", "api-key", "apikey", "x-api-key", "token", "cookie")

# Hosts that never leave the machine, where plain HTTP is not a finding.
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"})


def check_config_hygiene(servers: list[ConfiguredServer]) -> list[Finding]:
    """Report configured servers that are risky before they say anything."""
    findings: list[Finding] = []
    for server in servers:
        findings.extend(_check_launch(server))
        findings.extend(_check_secrets(server))
        findings.extend(_check_transport(server))
    return findings


def _check_launch(server: ConfiguredServer) -> list[Finding]:
    """Whether starting this server means running a script rather than a program."""
    if not server.command:
        return []

    reason = _shell_reason(server)
    if reason is None:
        return []

    return [
        _finding(
            SHELL_LAUNCH_RULE_ID,
            HIGH,
            server,
            f"launch command {reason}",
            server.launch_line,
            "No MCP server needs to be started through a shell -- a legitimate "
            "one names its binary. Replace this with the program and its "
            "arguments, or remove the server.",
        )
    ]


def _shell_reason(server: ConfiguredServer) -> str | None:
    """What is wrong with a launch line, in words, or None if nothing is."""
    program = _program_name(server.command)
    flags = {argument.lower() for argument in server.args}

    if program in SHELL_PROGRAMS and flags & SCRIPT_FLAGS:
        return f"runs a script through {program}"

    lowered = server.launch_line.lower()
    for marker in FETCH_AND_RUN_MARKERS:
        if marker in lowered:
            return "fetches or evaluates code at startup"

    return None


def _program_name(command: str) -> str:
    """The bare program being run, without its path or extension."""
    tail = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return tail.removesuffix(".exe")


def _check_secrets(server: ConfiguredServer) -> list[Finding]:
    """Credentials written into the config file rather than referenced from it."""
    findings: list[Finding] = []
    for where, values in (("env", server.env), ("headers", server.headers)):
        for name, value in values.items():
            if not _looks_like_a_written_secret(name, value):
                continue
            findings.append(
                _finding(
                    PLAINTEXT_SECRET_RULE_ID,
                    MEDIUM,
                    server,
                    f'{where} entry "{name}" looks like a credential written into the config',
                    f"{name}={_redact(value)}",
                    "Config files get committed, screen-shared and synced. Move "
                    "this into an environment variable and reference it, which "
                    "every client supports.",
                )
            )
    return findings


def _looks_like_a_written_secret(name: str, value: str) -> bool:
    """A secret-sounding name holding a literal value rather than a reference."""
    if not any(marker in name.lower() for marker in SECRET_NAME_MARKERS):
        return False
    if len(value) < SECRET_MINIMUM_LENGTH:
        return False
    # `${VAR}`, `$VAR` and `%VAR%` are references to a secret, not a secret.
    return not (value.startswith(("$", "%")) or "${" in value)


def _redact(value: str) -> str:
    """Enough of a value to recognise it, never enough to use it."""
    return f"{value[:4]}... ({len(value)} characters)"


def _check_transport(server: ConfiguredServer) -> list[Finding]:
    """How a remote server is reached, and whether anything proves who it is."""
    if not server.is_remote:
        return []

    findings: list[Finding] = []
    split = urlsplit(server.url)
    host = (split.hostname or "").lower()

    if split.scheme == "http" and host not in LOCAL_HOSTS:
        findings.append(
            _finding(
                INSECURE_TRANSPORT_RULE_ID,
                HIGH,
                server,
                "server is reached over plain HTTP",
                server.url,
                "Tool descriptions cross the network in clear and anyone on the "
                "path can rewrite them, which makes every other check here "
                "unenforceable. Use https, or move the server onto this machine.",
            )
        )

    if not _has_credentials(server):
        findings.append(
            _finding(
                NO_AUTH_RULE_ID,
                LOW,
                server,
                "remote server has no credential configured",
                server.url,
                "Sometimes correct. Confirm this server is meant to be open, "
                "and that you are the only one talking to it.",
            )
        )

    return findings


def _has_credentials(server: ConfiguredServer) -> bool:
    """Whether anything in the entry authenticates the connection."""
    if any(_is_auth_header(name) and value for name, value in server.headers.items()):
        return True
    return any(
        any(marker in name.lower() for marker in SECRET_NAME_MARKERS) and value
        for name, value in server.env.items()
    )


def _is_auth_header(name: str) -> bool:
    return any(marker in name.lower() for marker in AUTH_HEADER_MARKERS)


def _finding(
    rule_id: str,
    severity: str,
    server: ConfiguredServer,
    message: str,
    evidence: str,
    remediation: str,
) -> Finding:
    """One finding about one server, tagged so output says "server", not "tool"."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        tool_name=server.name,
        message=f"{message} (configured in {server.client})",
        evidence_snippet=f"{evidence}  [{server.source}]",
        remediation=remediation,
        subject_kind="server",
    )
