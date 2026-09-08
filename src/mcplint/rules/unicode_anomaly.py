"""Flags characters in a tool definition that you cannot see but the model can.

Why this rule exists
--------------------
The injection rule assumes you could catch the attack by reading the
description. This rule exists for the case where you could not, because the
text was never on the screen to begin with.

Three ways that happens, all of them cheap for an attacker:

*Invisible characters.* A zero-width space between two letters splits a word
for a pattern matcher while leaving it intact for a reader. Sprinkle a few
through "ignore previous instructions" and the injection rule no longer
matches, but the tokeniser still reads it fine.

*Tag characters.* The block at U+E0000-E007F maps one-to-one onto ASCII and
renders as nothing at all, in every font, everywhere. An attacker can encode a
whole paragraph of instructions in it and paste that into a description which
looks, on screen, like one clean sentence. This one is worth understanding: it
is not obfuscation, it is a second channel into the context window.

*Bidi overrides.* U+202E flips rendering direction, so the stored text and the
displayed text stop agreeing. What you review is not what gets sent.

Plus the homograph case: a Cyrillic "a" inside an otherwise-Latin word, which
is how one tool impersonates another in a list a human is skimming.

Everything here is `unicodedata` and set membership. The character tables sit
at the top of this file so you can widen them without hunting for a config.
They are written as escapes on purpose: a literal zero-width space in this
file would be exactly as invisible to you here as it is in an attack.
"""

import unicodedata

from mcplint.core import HIGH, MEDIUM, Finding, Tool

INVISIBLE_RULE_ID = "UNICODE_INVISIBLE"
BIDI_RULE_ID = "UNICODE_BIDI"
MIXED_SCRIPT_RULE_ID = "UNICODE_MIXED_SCRIPT"

# Characters that occupy no space and carry no meaning a reader can perceive.
# Legitimate in a handful of scripts, essentially never in an English tool
# description written by someone with nothing to hide.
INVISIBLE_CHARACTERS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u00ad": "SOFT HYPHEN",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u034f": "COMBINING GRAPHEME JOINER",
}

# Rendering-direction controls. An override in a tool description is not a
# formatting choice, it is an attempt to make visual review unreliable.
BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# The Unicode tag block. Subtract TAG_BLOCK_START from a codepoint in this
# range and you get the ASCII character it stands for, which is how a hidden
# payload is both written and read back out again.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# Script pairs no honest word mixes. A description containing both Latin and
# CJK is a bilingual description; a single *word* containing both Latin and
# Cyrillic is a homograph. Only the second is worth a finding, which is why
# this check runs per word rather than per description.
CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK"})

# How much surrounding text to show either side of a hit.
SNIPPET_PADDING = 30


def check_unicode_anomalies(tools: list[Tool]) -> list[Finding]:
    """Report invisible characters, bidi overrides and homographs in tool text.

    Both the name and the description are checked: a tool whose *name* contains
    a Cyrillic lookalike is impersonating another tool, and that is a finding
    even when its description is spotless.
    """
    findings: list[Finding] = []
    for tool in tools:
        for field_name, text in (("name", tool.name), ("description", tool.description)):
            findings.extend(_check_text(tool.name, field_name, text))
    return findings


def _check_text(tool_name: str, field_name: str, text: str) -> list[Finding]:
    """Run every character check over one field of one tool.

    Reports the first hit per category rather than one per character: a
    description seeded with forty zero-width spaces is one problem, not forty.
    """
    findings: list[Finding] = []

    invisible = _first_match(text, INVISIBLE_CHARACTERS)
    if invisible is not None:
        offset, character = invisible
        findings.append(
            Finding(
                rule_id=INVISIBLE_RULE_ID,
                severity=HIGH,
                tool_name=tool_name,
                message=(
                    f"{field_name} contains an invisible "
                    f"{INVISIBLE_CHARACTERS[character]} (U+{ord(character):04X}) "
                    f"at offset {offset}"
                ),
                evidence_snippet=_snippet(text, offset),
                remediation=(
                    "Invisible characters have no place in a tool definition. "
                    "Strip them, re-read what is left, and judge that."
                ),
            )
        )

    bidi = _first_match(text, BIDI_CONTROLS)
    if bidi is not None:
        offset, character = bidi
        findings.append(
            Finding(
                rule_id=BIDI_RULE_ID,
                severity=HIGH,
                tool_name=tool_name,
                message=(
                    f"{field_name} contains a {BIDI_CONTROLS[character]} "
                    f"(U+{ord(character):04X}) at offset {offset}"
                ),
                evidence_snippet=_snippet(text, offset),
                remediation=(
                    "The stored text and the displayed text do not agree. "
                    "Review the raw characters, not the rendering."
                ),
            )
        )

    smuggled = _decode_tag_characters(text)
    if smuggled:
        findings.append(
            Finding(
                rule_id=INVISIBLE_RULE_ID,
                severity=HIGH,
                tool_name=tool_name,
                message=(
                    f"{field_name} carries {len(smuggled)} Unicode tag characters, "
                    f"which render as nothing and decode to ASCII"
                ),
                evidence_snippet=f"decodes to: {smuggled!r}",
                remediation=(
                    "This is a hidden second channel into the model's context. "
                    "There is no benign reason for it. Do not connect this server."
                ),
            )
        )

    for word in _mixed_script_words(text):
        findings.append(
            Finding(
                rule_id=MIXED_SCRIPT_RULE_ID,
                severity=MEDIUM,
                tool_name=tool_name,
                message=f"{field_name} mixes scripts inside the word {word!r}",
                evidence_snippet=" ".join(f"U+{ord(character):04X}" for character in word),
                remediation=(
                    "Letters from another script can render identically to Latin "
                    "ones. Confirm this word is the word it appears to be."
                ),
            )
        )

    return findings


def _first_match(text: str, table: dict[str, str]) -> tuple[int, str] | None:
    """The offset and value of the first character of `text` found in `table`."""
    for offset, character in enumerate(text):
        if character in table:
            return offset, character
    return None


def _decode_tag_characters(text: str) -> str:
    """Map any Unicode tag characters back to the ASCII they stand for."""
    return "".join(
        chr(ord(character) - TAG_BLOCK_START)
        for character in text
        if TAG_BLOCK_START <= ord(character) <= TAG_BLOCK_END
    )


def _mixed_script_words(text: str) -> list[str]:
    """Words drawing their letters from more than one confusable script."""
    mixed: list[str] = []
    for word in text.split():
        scripts = {_script_of(character) for character in word if character.isalpha()}
        if len(scripts & CONFUSABLE_SCRIPTS) > 1:
            mixed.append(word)
    return mixed


def _script_of(character: str) -> str:
    """The script a character belongs to, read off the front of its Unicode name."""
    try:
        return unicodedata.name(character).split()[0]
    except ValueError:
        return ""


def _snippet(text: str, offset: int) -> str:
    """Context around an offset, with unprintable characters escaped so they show.

    A snippet that renders an invisible character as itself would be a snippet
    showing the user nothing, which defeats the point of having evidence.
    """
    start = max(0, offset - SNIPPET_PADDING)
    end = min(len(text), offset + SNIPPET_PADDING)
    window = "".join(
        character if character.isprintable() else f"<U+{ord(character):04X}>"
        for character in text[start:end]
    )
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    return f"{prefix}{window}{suffix}"
