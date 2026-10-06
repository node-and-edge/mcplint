"""The one part of mcplint that talks to anything.

Everything else in this package reads a file and does arithmetic on it. This
module spawns a process, speaks JSON-RPC to it over a pipe, and asks it for its
tool list. That is a categorically different kind of code, so it lives in a
categorically separate file: "no rule can reach the network" is a claim you
should be able to check by reading import lists, and you can -- nothing under
`rules/` imports this, and this imports no rule.

What it does, in order:

    initialize                  -> wait for the result
    notifications/initialized   -> no reply expected
    tools/list                  -> wait for the result

which is the whole MCP client handshake for a client that only wants to read
the menu. mcplint never calls a tool, never sends a prompt, and never sends
anything it read to anywhere. One round trip, then the process is killed.

Reading with a timeout is the fiddly part. A pipe read blocks, `select` does
not work on pipes on Windows, and a server that hangs must not hang the linter
-- so stdout is drained on a background thread into a queue and the main flow
takes from that queue with a deadline. That is the only reason there is a
thread in this project.

Spawning a process is a genuinely dangerous thing for a security tool to do on
the user's behalf, so it happens only when the user passes `--stdio-command`
explicitly. Nothing here guesses at a command to run, and no config file can
cause one to be spawned.
"""

import json
import queue
import subprocess
import threading
import time
from typing import Any

from mcplint.core import Tool, parse_tools

# The MCP revision this client announces. Servers negotiate down, so an older
# server answering a newer client is normal and not an error.
PROTOCOL_VERSION = "2024-11-05"

CLIENT_NAME = "mcplint"

# How long the whole handshake gets, start to finish. A server that cannot
# describe its own tools inside this is a server worth being suspicious of.
DEFAULT_TIMEOUT_SECONDS = 15.0

# How much of a failing server's stderr to quote back. Enough to see a stack
# trace's last line, not enough to fill a terminal.
STDERR_EXCERPT = 500

# How long a server gets to exit after being asked to, before it is killed.
SHUTDOWN_GRACE_SECONDS = 2.0

_INITIALIZE_ID = 1
_TOOLS_LIST_ID = 2


class StdioError(RuntimeError):
    """A server could not be started, could not be spoken to, or said no."""


def load_tools_from_stdio(
    command: str,
    args: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[Tool]:
    """Start an MCP server, ask it for its tools, and stop it again."""
    try:
        # The command is the user's own argument, spawned only because they
        # passed --stdio-command. Nothing here assembles one on their behalf.
        process = subprocess.Popen(
            [command, *(args or [])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as error:
        raise StdioError(f"could not start {command!r}: {error}") from error

    try:
        result = _handshake(process, timeout)
    finally:
        _stop(process)

    try:
        return parse_tools(result)
    except TypeError as error:
        raise StdioError(f"server answered tools/list without a tool list: {error}") from error


def _handshake(process: subprocess.Popen, timeout: float) -> Any:
    """Run the three-message exchange and return the `tools/list` result."""
    incoming = _drain_in_background(process.stdout)
    complaints = _collect_in_background(process.stderr)
    deadline = time.monotonic() + timeout

    _send(process, _request(_INITIALIZE_ID, "initialize", _client_details()))
    _await(incoming, _INITIALIZE_ID, deadline, complaints)

    _send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    _send(process, _request(_TOOLS_LIST_ID, "tools/list", {}))

    return _await(incoming, _TOOLS_LIST_ID, deadline, complaints)


def _client_details() -> dict[str, Any]:
    """What mcplint tells a server about itself. Deliberately unremarkable."""
    from mcplint import __version__

    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": __version__},
    }


def _request(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def _send(process: subprocess.Popen, message: dict[str, Any]) -> None:
    """Write one newline-delimited JSON-RPC message to the server's stdin."""
    try:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError) as error:
        raise StdioError(f"server stopped reading: {error}") from error


def _drain_in_background(stream) -> queue.Queue:
    """Pull lines off a pipe on a thread so the reader below can time out.

    Ends the queue with `None` when the pipe closes, so a server that exits
    without answering surfaces as a clear error rather than as a timeout the
    user has to sit through.
    """
    lines: queue.Queue = queue.Queue()

    def pump() -> None:
        try:
            for line in stream:
                lines.put(line)
        except (OSError, ValueError):
            # `_stop` closed the pipe from under us on the way out. That is the
            # normal end of this thread, not something to report.
            pass
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    return lines


def _await(incoming: queue.Queue, request_id: int, deadline: float, complaints: list[str]) -> Any:
    """Read until the answer to one request arrives, or the deadline passes.

    Anything that is not that answer is skipped rather than rejected: servers
    emit notifications, progress messages and the occasional line of plain log
    output on stdout, and none of that is our business here.
    """
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StdioError(f"server did not answer within {DEFAULT_TIMEOUT_SECONDS:.0f}s")

        try:
            line = incoming.get(timeout=remaining)
        except queue.Empty:
            raise StdioError("server did not answer in time") from None

        if line is None:
            raise StdioError(f"server exited without answering{_excerpt(complaints)}")

        message = _parse(line)
        if message is None or message.get("id") != request_id:
            continue

        if "error" in message:
            raise StdioError(f"server returned an error: {message['error']}")
        return message.get("result")


def _parse(line: str) -> dict[str, Any] | None:
    """One line as a JSON-RPC message, or None if it was not one."""
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        return None
    return message if isinstance(message, dict) else None


def _collect_in_background(stream) -> list[str]:
    """Gather a pipe's output on a thread, so reading it back can never block.

    Reading a live process's stderr directly blocks until that process exits,
    which would hang the linter on exactly the broken server it is trying to
    describe. Collecting as it arrives means the text is simply there when a
    failure needs explaining.
    """
    collected: list[str] = []

    def pump() -> None:
        try:
            collected.extend(stream)
        except (OSError, ValueError):
            pass

    threading.Thread(target=pump, daemon=True).start()
    return collected


def _excerpt(complaints: list[str]) -> str:
    """Whatever the server said on stderr, if it said anything."""
    text = "".join(complaints).strip()
    return f": {text[:STDERR_EXCERPT]}" if text else ""


def _stop(process: subprocess.Popen) -> None:
    """End the server, politely and then not.

    A linter that leaves a subprocess behind on every run is a worse problem
    than whatever it was linting for.

    The order here is load-bearing and was not obvious. Closing an output pipe
    while a pump thread is blocked reading it deadlocks: `close()` waits for a
    lock that the blocked read is holding, and the read only ends when the pipe
    does. So the process has to die first -- that puts an EOF in front of both
    readers, they return, and only then is closing safe. Closing stdout first
    hangs the linter on exactly the crashed server it was trying to describe.
    """
    # stdin is the one pipe no thread is reading, so it can go immediately --
    # and closing it is how a well-behaved server is asked to shut down.
    _close(process.stdin)

    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=SHUTDOWN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=SHUTDOWN_GRACE_SECONDS)

    _close(process.stdout)
    _close(process.stderr)


def _close(stream) -> None:
    """Close a pipe, tolerating one that is already gone."""
    try:
        stream.close()
    except (OSError, ValueError):
        pass
