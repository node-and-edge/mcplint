"""Flags the descriptions on a server that do not look like the others.

Why this rule exists
--------------------
Every other rule here knows what it is looking for -- a phrase, a codepoint, an
unbounded parameter. This one does not. It looks for a description wildly out
of proportion with its neighbours, on the theory that whatever an attacker
needs to say takes room, and room stays visible even when the words are not
recognisable.

That matters because the injection rule can be worded around. Paraphrase the
instruction, avoid every phrase in the list, and it sails through. What is much
harder to hide is that you needed nine hundred characters to say what the other
eleven tools said in eighty. Tool-poisoning payloads are long: they set a
scene, establish authority, give the instruction, then explain why the user
must not be told. That is a paragraph, and a paragraph standing next to a
one-line description is a shape you can measure without understanding a word
of it.

It is also a plain quality signal with no attacker involved. A description four
times longer than its neighbours spends your context budget on every request,
forever, and usually means one tool is doing the work of four.

This is the weakest rule in the project and is scored LOW to say so. It is a
"go and read this one" prompt, not an accusation.

A note on the statistics, because the obvious version of this is wrong
---------------------------------------------------------------------
The tempting approach -- take the mean and standard deviation of every
description, flag anything more than N deviations out -- fails on exactly the
input it is meant to catch. A large outlier drags the mean towards itself and
inflates the deviation it is then measured against, so it masks itself. With
population statistics over n samples, no value can sit further than sqrt(n-1)
deviations from the mean no matter how extreme it is; on a five-tool server
that ceiling is 2.0, so a threshold of 3.0 would look perfectly reasonable in
review and never once fire.

Leaving each value out of its own baseline fixes that for a single outlier and
then fails again for two, because each one inflates the baseline the other is
measured against. A server with three poisoned tools is not a strange case --
it is what shadowing looks like.

So the comparison is against the *median*, with the median absolute deviation
as the spread: the modified z-score. Both halves of it are unmoved by up to
half the sample being outliers, which is the property this needs and the mean
does not have. `MODIFIED_Z_SCALE` is the usual constant that lines it up with
an ordinary z-score on normally distributed data, so `MODIFIED_Z_THRESHOLD`
reads on the familiar scale.
"""

import statistics

from mcplint.core import LOW, Finding, Tool

RULE_ID = "DESCRIPTION_OUTLIER"
SEVERITY = LOW

# Below this many tools there is no "normal for this server" to be unlike, and
# a spread computed from three samples is noise wearing a number's clothes.
MINIMUM_TOOLS = 5

# Scales the median absolute deviation so the score below reads on roughly the
# same scale as an ordinary z-score, and the threshold means what you expect.
MODIFIED_Z_SCALE = 0.6745
MODIFIED_Z_THRESHOLD = 3.5

# Two independent floors, so a finding always means something in plain terms as
# well as in statistical ones. A description has to be long in absolute terms,
# and long relative to the median, before the score gets a say. Without these,
# a server whose descriptions are all near-identical would flag the one that
# happens to be nine characters longer.
MINIMUM_LENGTH = 300
MINIMUM_RATIO = 2.0


def check_description_outliers(tools: list[Tool]) -> list[Finding]:
    """Report descriptions far longer than the rest of the same server's tools.

    Three gates, all of which must open: absolute length, ratio to the median,
    and distance from the median in robust deviations. Any one of them alone
    produces noise on some perfectly ordinary server.
    """
    if len(tools) < MINIMUM_TOOLS:
        return []

    lengths = [len(tool.description) for tool in tools]
    median = statistics.median(lengths)
    deviation = _median_absolute_deviation(lengths, median)

    findings: list[Finding] = []
    for tool, length in zip(tools, lengths):
        if length < MINIMUM_LENGTH:
            continue

        ratio = length / median if median else float("inf")
        if ratio < MINIMUM_RATIO:
            continue

        if _modified_z_score(length, median, deviation) < MODIFIED_Z_THRESHOLD:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity=SEVERITY,
                tool_name=tool.name,
                message=(
                    f"description is {ratio:.1f}x the median length on this server "
                    f"({length} characters against a median of {median:.0f})"
                ),
                evidence_snippet=_opening(tool.description),
                remediation=(
                    "Read this description in full. Either it is carrying an "
                    "instruction the other rules did not recognise, or the tool "
                    "is doing enough things to be several tools -- and either way "
                    "it is spending context on every request."
                ),
            )
        )
    return findings


def _median_absolute_deviation(lengths: list[int], median: float) -> float:
    """The median of how far each length sits from the median length."""
    return statistics.median([abs(length - median) for length in lengths])


def _modified_z_score(length: int, median: float, deviation: float) -> float:
    """How far one length sits from the median, in robust deviations.

    A deviation of zero means over half the descriptions are exactly the median
    length. That is not a degenerate case to guard against, it is the common
    shape of a tidy server -- and anything standing above such a wall of
    agreement is as much of an outlier as arithmetic can express.
    """
    if length <= median:
        return 0.0
    if deviation == 0:
        return float("inf")
    return MODIFIED_Z_SCALE * (length - median) / deviation


# How much of the description to quote back, so the user has somewhere to start
# reading without the whole payload landing in their terminal.
OPENING_LENGTH = 120


def _opening(description: str) -> str:
    """The start of the description, collapsed to one line."""
    collapsed = " ".join(description.split())
    suffix = "..." if len(collapsed) > OPENING_LENGTH else ""
    return f"{collapsed[:OPENING_LENGTH]}{suffix}"
