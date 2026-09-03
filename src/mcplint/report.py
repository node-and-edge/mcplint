"""Turns a list of findings into whatever the user asked to look at.

Rules return data and never print. This is where that data becomes text, and
that split is what keeps rules independently testable -- it is also why "no
rule can make a network call" is a claim you can check rather than one you have
to believe.

Three formats, one function each:

    render_text()   what you read in a terminal
    render_json()   what a script reads
    render_sarif()  what GitHub code scanning reads

The text renderer is the one that matters; the other two are serialisation
with no opinions in them. All three take the same `list[Finding]` and none of
them can change what was found.

One thing worth knowing about SARIF: it wants a description for every rule it
sees, and the only place those could live is a table in this file. A table like
that goes stale the moment somebody adds a rule and forgets it, so there is a
test asserting that every rule id the tool can emit has an entry here. That is
the sort of thing you only find out about six months later otherwise.
"""

import json
from typing import Any

from mcplint import __version__
from mcplint.core import HIGH, LOW, MEDIUM, Finding

# ---------------------------------------------------------------------------
# Text — what you read in a terminal
# ---------------------------------------------------------------------------

# Width of the rule-id column, so messages line up in the common case.
RULE_ID_WIDTH = 20


def render_text(findings: list[Finding], subject_count: int, subject: str = "tools") -> str:
    """Render findings grouped by subject, followed by a one-line summary."""
    if not findings:
        return f"No findings across {subject_count} {subject}."

    lines: list[str] = []
    for tool_name in _subject_order(findings):
        kind = next(f.subject_kind for f in findings if f.tool_name == tool_name)
        lines.append(f"  {kind}: {visible(tool_name)}")
        for finding in findings:
            if finding.tool_name != tool_name:
                continue
            label = f"[{finding.severity}]"
            lines.append(f"  {label:<8} {finding.rule_id:<{RULE_ID_WIDTH}} {finding.message}")
            if finding.evidence_snippet:
                lines.append(f"  {'':<8} {'':<{RULE_ID_WIDTH}} {finding.evidence_snippet}")
        lines.append("")

    lines.append(_summary(findings, subject_count, subject))
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


def _subject_order(findings: list[Finding]) -> list[str]:
    """Subject names in the order they first appear, without duplicates."""
    seen: list[str] = []
    for finding in findings:
        if finding.tool_name not in seen:
            seen.append(finding.tool_name)
    return seen


def _summary(findings: list[Finding], subject_count: int, subject: str = "tools") -> str:
    counts = {severity: 0 for severity in (HIGH, MEDIUM, LOW)}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(f"{counts[level]} {level.lower()}" for level in (HIGH, MEDIUM, LOW))
    noun = "finding" if len(findings) == 1 else "findings"
    return f"{len(findings)} {noun} across {subject_count} {subject}. {breakdown}."


# ---------------------------------------------------------------------------
# SARIF — what GitHub code scanning reads
# ---------------------------------------------------------------------------

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
PROJECT_URL = "https://github.com/node-and-edge/mcplint"

# SARIF has three levels where this tool has three severities, which is lucky,
# because a mapping that lost information here would quietly change what a
# reviewer sees in a pull request.
SARIF_LEVELS = {HIGH: "error", MEDIUM: "warning", LOW: "note"}

# One line per rule id, for the rule descriptors SARIF wants alongside results.
# Kept complete by a test rather than by memory -- see the note at the top.
RULE_DESCRIPTIONS = {
    "INJECTION_PHRASE": "A tool description contains known instruction-hijack phrasing.",
    "UNICODE_INVISIBLE": "A tool definition contains characters that render as nothing.",
    "UNICODE_BIDI": "A tool definition contains text-direction overrides.",
    "UNICODE_MIXED_SCRIPT": "A tool name or description mixes confusable alphabets.",
    "PERMISSIVE_SCHEMA": "A dangerous-sounding parameter accepts any string at all.",
    "DESCRIPTION_OUTLIER": "A description is far longer than the rest of the server's.",
    "SHADOWED_TOOL_NAME": "More than one tool answers to the same name.",
    "TOOL_ADDED": "A tool appeared that was not present when the server was pinned.",
    "TOOL_REMOVED": "A tool present when the server was pinned is gone.",
    "TOOL_REDEFINED": "A tool changed definition under a name already reviewed.",
    "CONFIG_SHELL_LAUNCH": "A configured server is started through a shell.",
    "CONFIG_PLAINTEXT_SECRET": "A credential is written into a client config file.",
    "CONFIG_INSECURE_TRANSPORT": "A remote server is reached over plain HTTP.",
    "CONFIG_NO_AUTH": "A remote server has no credential configured.",
}


def render_sarif(findings: list[Finding], source: str) -> str:
    """Render findings as SARIF 2.1.0, for GitHub code scanning and friends."""
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcplint",
                        "version": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": _rule_descriptors(findings),
                    }
                },
                "results": [_sarif_result(finding, source) for finding in findings],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=True)


def _rule_descriptors(findings: list[Finding]) -> list[dict[str, Any]]:
    """One descriptor per rule that actually reported something."""
    seen: list[str] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen.append(finding.rule_id)

    return [
        {
            "id": rule_id,
            "name": rule_id.title().replace("_", ""),
            "shortDescription": {"text": describe(rule_id)},
            "fullDescription": {"text": describe(rule_id)},
            "defaultConfiguration": {"level": _worst_level(findings, rule_id)},
            "helpUri": PROJECT_URL,
        }
        for rule_id in seen
    ]


def describe(rule_id: str) -> str:
    """One line about a rule, or an honest placeholder if nobody wrote one."""
    return RULE_DESCRIPTIONS.get(rule_id, f"mcplint rule {rule_id}.")


def _worst_level(findings: list[Finding], rule_id: str) -> str:
    """The most severe level this rule reported, as SARIF spells it."""
    for severity in (HIGH, MEDIUM, LOW):
        if any(f.rule_id == rule_id and f.severity == severity for f in findings):
            return SARIF_LEVELS[severity]
    return "note"


def _sarif_result(finding: Finding, source: str) -> dict[str, Any]:
    """One finding as a SARIF result.

    The location is the file or server the findings came from, not a line in
    it: there are no line numbers here, because a tool list is data a server
    sent rather than source anyone can point at. The tool name goes in a
    logical location instead, which is what SARIF has for exactly this.
    """
    return {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVELS.get(finding.severity, "note"),
        "message": {"text": _sarif_message(finding)},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": source}},
                "logicalLocations": [
                    {"name": finding.tool_name, "kind": finding.subject_kind},
                ],
            }
        ],
        "properties": {
            "subject": finding.tool_name,
            "subjectKind": finding.subject_kind,
            "severity": finding.severity,
            "evidence": finding.evidence_snippet,
            "remediation": finding.remediation,
        },
    }


def _sarif_message(finding: Finding) -> str:
    """The finding, its evidence and its remedy in one readable block.

    A code scanning comment shows the message and little else, so anything left
    only in `properties` is effectively invisible to the person reading it.
    """
    parts = [f"{finding.subject_kind} {finding.tool_name!r}: {finding.message}"]
    if finding.evidence_snippet:
        parts.append(f"Evidence: {finding.evidence_snippet}")
    if finding.remediation:
        parts.append(finding.remediation)
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# JSON — what a script reads
# ---------------------------------------------------------------------------


def render_json(findings: list[Finding], subject_count: int, subject: str = "tools") -> str:
    """Render findings as plain JSON, with the counts the summary line carries.

    Deliberately not SARIF-shaped. SARIF exists to be consumed by one
    particular family of tools and reads like it; this is for the shell script
    somebody writes on a Tuesday.
    """
    document = {
        "version": __version__,
        "subject": subject,
        "subject_count": subject_count,
        "counts": {
            severity.lower(): sum(1 for f in findings if f.severity == severity)
            for severity in (HIGH, MEDIUM, LOW)
        },
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "subject": finding.tool_name,
                "subject_kind": finding.subject_kind,
                "message": finding.message,
                "evidence": finding.evidence_snippet,
                "remediation": finding.remediation,
            }
            for finding in findings
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=True)
