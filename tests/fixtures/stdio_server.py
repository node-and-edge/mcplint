"""A minimal MCP server over stdio, for testing the stdio loader against.

Not a fixture in the JSON sense -- it is a real process the tests spawn, so the
loader is exercised the way it will be used rather than against a mock of a
pipe. It takes a mode argument so one file can play every server worth testing
against, including the badly behaved ones:

    clean    answers the handshake and returns a tidy tool list
    poisoned answers the handshake and returns a tool list full of problems
    noisy    prints log lines to stdout before answering, as real servers do
    error    answers `initialize`, then refuses `tools/list`
    crash    writes a complaint to stderr and exits without answering
    hang     answers nothing at all, ever

No network, no dependencies. Run it by hand to see what the loader sees:

    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | \
        python tests/fixtures/stdio_server.py clean
"""

import json
import sys
import time
from pathlib import Path

FIXTURES = Path(__file__).parent

TOOL_LISTS = {
    "clean": "clean_tools.json",
    "poisoned": "poisoned_everything.json",
    "noisy": "clean_tools.json",
    "error": "clean_tools.json",
}


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def result(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "clean"

    if mode == "crash":
        sys.stderr.write("mcp-test-server: config file not found\n")
        sys.stderr.flush()
        return 1

    if mode == "hang":
        time.sleep(3600)
        return 0

    tools = json.loads((FIXTURES / TOOL_LISTS[mode]).read_text(encoding="utf-8"))

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        method = request.get("method")

        if method == "initialize":
            send(
                result(
                    request["id"],
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mcp-test-server", "version": "0.0.1"},
                    },
                )
            )
            if mode == "noisy":
                # Real servers put startup logging on stdout and expect the
                # client to step over anything that is not a reply to it.
                sys.stdout.write("listening on stdio\n")
                sys.stdout.write('{"jsonrpc":"2.0","method":"notifications/progress"}\n')
                sys.stdout.flush()

        elif method == "tools/list":
            if mode == "error":
                send(
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32601, "message": "tools are not enumerable"},
                    }
                )
            else:
                send(result(request["id"], tools))

    return 0


if __name__ == "__main__":
    sys.exit(main())
