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

This function is the half that needs no memory: read one list, report any name
claimed more than once. It is nearly free, because the list is already parsed.

Names are compared case-insensitively as well as exactly, because two tools
called `read_file` and `Read_File` are one ambiguity, not two tools -- to a
model choosing between them they read as the same word.
"""

from collections import defaultdict

from mcplint.core import HIGH, MEDIUM, Finding, Tool

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
