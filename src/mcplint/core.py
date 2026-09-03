"""Everything between the CLI and the rules, in one file, in data-flow order.

Read it top to bottom and you have read the whole pipeline:

    load_tools_from_json()  ->  list[Tool]
    run_all()               ->  list[Finding]
    render_text()           ->  the text a human sees

The four sections below used to be four modules. They are here together
because none of them is more than a screen long, and a reader chasing the flow
of a scan should not have to open four files to follow it. The rules stay in
their own files under `rules/` — those are the part you are meant to audit one
at a time.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 1. Data shapes
# ---------------------------------------------------------------------------

# Severity labels. Plain strings rather than an Enum so a finding stays
# trivially printable and JSON-serialisable later on.
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"

# Lets the CLI answer "is this finding at least as bad as our threshold?"
# without anyone having to remember the ordering by hand.
SEVERITY_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


@dataclass
class Tool:
    """One tool, exactly as an MCP server describes it in `tools/list`.

    `description` is the interesting field: it is pasted into the model's
    context with instruction-level authority, which is what the rules in this
    project are looking at.
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """One problem, in one tool, spotted by one rule.

    `evidence_snippet` matters as much as `message`: a finding the user cannot
    verify by eye is a finding they have to take on faith, and taking things on
    faith is the thing this project exists to avoid.
    """

    rule_id: str
    severity: str
    tool_name: str
    message: str
    evidence_snippet: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# 2. Input — the zero-network path
# ---------------------------------------------------------------------------
# This opens a file, parses JSON, and hands back `list[Tool]`. Nothing here
# opens a socket or spawns a process. The stdio path (spawning a server for a
# real `tools/list` round trip) is the only part of the project allowed to
# touch the network, and it does not exist yet.


def load_tools_from_json(path: str | Path) -> list[Tool]:
    """Load tools from a JSON file on disk."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_tools(raw)


def parse_tools(raw: Any) -> list[Tool]:
    """Turn already-parsed JSON into `Tool` objects.

    A real `tools/list` response is shaped `{"tools": [...]}`, but people
    routinely save just the array out of a debugger. Both are accepted so
    nobody has to reshape a file by hand before scanning it.
    """
    entries = raw.get("tools", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise TypeError("expected a list of tools, or an object with a 'tools' key")

    tools: list[Tool] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise TypeError(f"expected each tool to be an object, got {type(entry).__name__}")
        tools.append(
            Tool(
                name=entry.get("name") or "<unnamed>",
                # A missing description is not an error — it is just nothing to
                # scan. Normalising to "" keeps every rule free of None checks.
                description=entry.get("description") or "",
                # MCP spells this `inputSchema`; we use snake_case internally.
                input_schema=entry.get("inputSchema") or {},
            )
        )
    return tools


# ---------------------------------------------------------------------------
# 3. Registry — the one list of rules
# ---------------------------------------------------------------------------
# Adding a rule is two steps: write the module, then add its function to the
# tuple in `run_all`. No discovery, no entry points, no decorators. If a rule
# is not in that tuple it does not run, and you can see every rule the tool has
# by reading one line.


def run_all(tools: list[Tool]) -> list[Finding]:
    """Run every registered rule over every tool and collect the findings."""
    # Imported here rather than at the top of the file: rule modules import
    # `Tool` and `Finding` from this module, so a top-level import back into
    # `rules` would be circular.
    from mcplint.rules import injection, unicode_anomaly

    rules = (
        injection.check_injection_phrases,
        unicode_anomaly.check_unicode_anomalies,
    )

    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule(tools))
    return findings


# ---------------------------------------------------------------------------
# 4. Output
# ---------------------------------------------------------------------------
# Rules return data and never print; this is where that data becomes text.
# That split is what keeps rules independently testable, and it is why "no rule
# can make a network call" is a checkable claim rather than a promise.

# Width of the rule-id column, so messages line up in the common case.
RULE_ID_WIDTH = 20


def render_text(findings: list[Finding], tool_count: int) -> str:
    """Render findings grouped by tool, followed by a one-line summary."""
    if not findings:
        return f"No findings across {tool_count} tools."

    lines: list[str] = []
    for tool_name in _tool_order(findings):
        lines.append(f"  tool: {visible(tool_name)}")
        for finding in findings:
            if finding.tool_name != tool_name:
                continue
            label = f"[{finding.severity}]"
            lines.append(f"  {label:<8} {finding.rule_id:<{RULE_ID_WIDTH}} {finding.message}")
            if finding.evidence_snippet:
                lines.append(f"  {'':<8} {'':<{RULE_ID_WIDTH}} {finding.evidence_snippet}")
        lines.append("")

    lines.append(_summary(findings, tool_count))
    return "\n".join(lines)


def visible(text: str) -> str:
    """Text with unprintable characters replaced by their codepoints.

    Echoing a tool name back exactly as the server sent it would let a name
    containing a zero-width space print as though it were clean -- in the
    output of the tool whose entire job is to say that it is not.
    """
    return "".join(
        character if character.isprintable() else f"<U+{ord(character):04X}>" for character in text
    )


def _tool_order(findings: list[Finding]) -> list[str]:
    """Tool names in the order they first appear, without duplicates."""
    seen: list[str] = []
    for finding in findings:
        if finding.tool_name not in seen:
            seen.append(finding.tool_name)
    return seen


def _summary(findings: list[Finding], tool_count: int) -> str:
    counts = {severity: 0 for severity in (HIGH, MEDIUM, LOW)}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(f"{counts[level]} {level.lower()}" for level in (HIGH, MEDIUM, LOW))
    noun = "finding" if len(findings) == 1 else "findings"
    return f"{len(findings)} {noun} across {tool_count} tools. {breakdown}."
