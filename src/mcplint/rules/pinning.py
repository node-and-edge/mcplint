"""Flags two tools laying claim to the same name.

Why this rule exists
--------------------
A model does not call a tool by identity. It calls it by name, from a flat list
it was handed, and nothing in that list says which server each entry came from
or which one was there yesterday. Name is the only handle there is, so anyone
who can put a name into the list can decide what that name means.

That gives two attacks, and they are the same attack from different ends.

*Shadowing.* A second server registers a tool called `read_file`, describing it
a little more helpfully than the real one. Now two entries answer to the same
name and the model picks one. Nothing was overwritten and nothing errored; the
list simply has an ambiguity in it that no one is looking at. Read a merged
tool list from three servers and you will not spot a repeat by eye.

*Rug pulls.* One server, one name, and the description changes a week after you
reviewed it -- audited on Monday, poisoned on Friday, with the same name and the
same schema. Catching that needs memory of what the tool used to be, which is
what `mcplint pin` and `mcplint diff` are for.

`check_shadowed_names` is the half that needs no memory: read one list, report
any name claimed more than once. It is nearly free, because the list is already
parsed. Names are compared case-insensitively as well as exactly, because
`read_file` and `Read_File` are one ambiguity rather than two tools -- a model
choosing between them reads the same word twice.

`fingerprint_tools` and `check_against_baseline` are the half that remembers.
A fingerprint is a hash of the description and a hash of the schema, kept
separately so a diff can say which of the two moved. Nothing but hashes and a
length is stored: a baseline is a file you commit, and it should not be a copy
of every description on a server you do not trust.

Neither function touches the disk. Reading and writing the baseline file lives
in `core.py`, so every rule module in this package remains incapable of I/O --
which is a far stronger guarantee than a promise in a README that none of them
performs any.
"""

import hashlib
import json
from collections import defaultdict
from typing import Any

from mcplint.core import HIGH, LOW, MEDIUM, Finding, Tool

RULE_ID = "SHADOWED_TOOL_NAME"

# An exact repeat is unambiguous: the list contains two answers to one question.
EXACT_SEVERITY = HIGH

# A repeat that differs only in capitalisation might be sloppiness rather than
# an attack, so it is scored a step down -- but it is still two entries a model
# has no way to tell apart.
CASE_INSENSITIVE_SEVERITY = MEDIUM

# How much of each competing description to quote, so the user can see at a
# glance whether the duplicates are the same tool twice or two different tools
# wearing one name.
OPENING_LENGTH = 70


def check_shadowed_names(tools: list[Tool]) -> list[Finding]:
    """Report every tool name claimed by more than one tool in the list."""
    findings: list[Finding] = []

    by_name: dict[str, list[Tool]] = defaultdict(list)
    for tool in tools:
        by_name[tool.name].append(tool)

    for name, claimants in by_name.items():
        if len(claimants) > 1:
            findings.append(
                _finding(
                    claimants,
                    EXACT_SEVERITY,
                    f'{len(claimants)} tools are declared with the name "{name}"',
                )
            )

    by_folded_name: dict[str, list[Tool]] = defaultdict(list)
    for tool in tools:
        by_folded_name[tool.name.casefold()].append(tool)

    for claimants in by_folded_name.values():
        spellings = sorted({tool.name for tool in claimants})
        # A single spelling was already reported above as an exact repeat; only
        # the differing-capitalisation case is new here.
        if len(claimants) > 1 and len(spellings) > 1:
            listed = " and ".join(f'"{spelling}"' for spelling in spellings)
            findings.append(
                _finding(
                    claimants,
                    CASE_INSENSITIVE_SEVERITY,
                    f"{listed} differ only in capitalisation",
                )
            )

    return findings


def _finding(claimants: list[Tool], severity: str, message: str) -> Finding:
    """One finding covering every tool competing for one name."""
    return Finding(
        rule_id=RULE_ID,
        severity=severity,
        tool_name=claimants[0].name,
        message=message,
        evidence_snippet=" | ".join(_opening(tool.description) for tool in claimants),
        remediation=(
            "A model picks a tool by name and cannot see that there are two. "
            "Find out which server each came from and remove or rename one "
            "before connecting them together."
        ),
    )


def _opening(description: str) -> str:
    """The start of a description, collapsed to one line."""
    collapsed = " ".join(description.split()) or "(no description)"
    suffix = "..." if len(collapsed) > OPENING_LENGTH else ""
    return f"{collapsed[:OPENING_LENGTH]}{suffix}"


# ---------------------------------------------------------------------------
# The half that remembers
# ---------------------------------------------------------------------------

ADDED_RULE_ID = "TOOL_ADDED"
REMOVED_RULE_ID = "TOOL_REMOVED"
REDEFINED_RULE_ID = "TOOL_REDEFINED"

# A tool that quietly became a different tool under a name you already reviewed
# is the whole reason this file exists.
REDEFINED_SEVERITY = HIGH

# A tool that appeared since you last looked has not been reviewed by anyone.
# Scored so that a default CI run stops and makes somebody read it.
ADDED_SEVERITY = MEDIUM

# A tool that went away cannot hurt you. Worth saying, not worth failing over.
REMOVED_SEVERITY = LOW


def fingerprint_tools(tools: list[Tool]) -> dict[str, dict[str, Any]]:
    """Reduce each tool to what a later run needs to notice it changed."""
    return {
        tool.name: {
            "description": _hash(tool.description),
            "schema": _hash(_canonical_json(tool.input_schema)),
            "description_length": len(tool.description),
        }
        for tool in tools
    }


def check_against_baseline(tools: list[Tool], baseline: dict[str, dict[str, Any]]) -> list[Finding]:
    """Report what changed between a pinned tool list and the current one."""
    current = fingerprint_tools(tools)
    descriptions = {tool.name: tool.description for tool in tools}
    findings: list[Finding] = []

    for name in current:
        if name not in baseline:
            findings.append(
                Finding(
                    rule_id=ADDED_RULE_ID,
                    severity=ADDED_SEVERITY,
                    tool_name=name,
                    message="tool was not present when this server was pinned",
                    evidence_snippet=_opening(descriptions.get(name, "")),
                    remediation=(
                        "Nobody has reviewed this tool. Read its description and "
                        "schema, then re-pin to accept it."
                    ),
                )
            )

    for name in baseline:
        if name not in current:
            findings.append(
                Finding(
                    rule_id=REMOVED_RULE_ID,
                    severity=REMOVED_SEVERITY,
                    tool_name=name,
                    message="tool was present when this server was pinned and is gone now",
                    evidence_snippet="",
                    remediation=(
                        "Usually harmless. Confirm you are pointed at the server "
                        "you think you are, then re-pin."
                    ),
                )
            )

    for name, pinned in baseline.items():
        if name not in current:
            continue
        changed = _changed_parts(pinned, current[name])
        if changed:
            findings.append(
                Finding(
                    rule_id=REDEFINED_RULE_ID,
                    severity=REDEFINED_SEVERITY,
                    tool_name=name,
                    message=f"{' and '.join(changed)} changed since this server was pinned",
                    evidence_snippet=_length_change(pinned, current[name]),
                    remediation=(
                        "The name you reviewed now means something else. Read the "
                        "new definition in full before running anything against "
                        "this server, then re-pin only if you accept it."
                    ),
                )
            )

    return findings


def _changed_parts(pinned: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Which halves of a fingerprint stopped matching."""
    return [part for part in ("description", "schema") if pinned.get(part) != current[part]]


def _length_change(pinned: dict[str, Any], current: dict[str, Any]) -> str:
    """How the description's size moved, since its text is deliberately not kept."""
    before = pinned.get("description_length")
    after = current["description_length"]
    if before is None or before == after:
        return ""
    return f"description length {before} -> {after} characters"


def _canonical_json(value: Any) -> str:
    """A schema rendered so that key order cannot make it look changed."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
