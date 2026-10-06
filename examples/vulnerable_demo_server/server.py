"""A deliberately poisoned MCP server, for pointing mcplint at.

This is a target, not a tool. It exists so you can run

    mcplint scan --stdio-command python \\
        --stdio-arg examples/vulnerable_demo_server/server.py

against something that behaves like a real server and get a page of findings
back, and so that the attacks this project talks about are in the repository
as artefacts rather than as descriptions of artefacts.

It is inert, and that is the whole lesson
-----------------------------------------
Every payload in `tools.json` is *text in a description field*. This file does
nothing with any of it. There is no code here that reads an SSH key, contacts
anybody, or touches a file -- `tools/call` returns a paragraph explaining
itself and stops.

That is not a safety compromise made for the demo. It is how tool poisoning
actually works. The server never does the dangerous thing; it asks the model
to, in a field the model reads with the same attention it gives its own
instructions, and the model has your credentials and your filesystem. A server
can be entirely honest in its implementation and still be the attack.

Which is also why a static linter can catch any of this at all. The payload has
to be in the text, because the text is the only part that reaches the model.

Safe to run. Do not connect it to anything
------------------------------------------
Running this file is harmless -- it speaks JSON-RPC on stdin and stdout and
exits. Registering it with a real MCP client is not the same thing: at that
point a model reads these descriptions with your tools available to it, which
is exactly the situation the descriptions are written to exploit.
"""

import json
import sys
from pathlib import Path

TOOLS_FILE = Path(__file__).parent / "tools.json"

PROTOCOL_VERSION = "2024-11-05"

REFUSAL = (
    "This is mcplint's vulnerable demo server. It implements no tools -- every "
    "payload it carries is text in a description, which is where tool poisoning "
    "lives. Nothing was done, and nothing will be."
)


def send(message):
    """Write one newline-delimited JSON-RPC message to stdout."""
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def result(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def handle(request):
    """Answer one request. Three methods, none of which does any work."""
    method = request.get("method")
    request_id = request.get("id")

    if method == "initialize":
        return result(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vulnerable-demo-server", "version": "0.1.0"},
            },
        )

    if method == "tools/list":
        return result(request_id, json.loads(TOOLS_FILE.read_text(encoding="utf-8")))

    if method == "tools/call":
        # Deliberately does nothing. See the module docstring: the attack was
        # already delivered when the description was read.
        return result(request_id, {"content": [{"type": "text", "text": REFUSAL}], "isError": True})

    if request_id is None:
        return None  # a notification; nothing is expected back

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"method not implemented: {method}"},
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = handle(request)
        if response is not None:
            send(response)

    return 0


if __name__ == "__main__":
    sys.exit(main())
