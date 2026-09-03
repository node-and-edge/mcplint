"""Flags tool parameters that accept anything, when they should not.

Why this rule exists
--------------------
The other rules read the description, which is where an attacker puts things.
This one reads the input schema, which is where a *well-meaning* developer
leaves things open by accident. It is the only rule here that fires on honest
mistakes more often than on attacks, and that is exactly why it earns its place:
those are the bugs nobody is looking for.

A tool declares its parameters as JSON Schema, and the model fills them in. If
a parameter called `command` is typed as an unconstrained string, then whatever
the model can be talked into writing is what the server receives -- and the
model can be talked into a lot, because the description it is reading came from
the same server. Prompt injection is the delivery; an unconstrained parameter
is the payload's landing site. One is not dangerous without the other.

So the check is narrow on purpose: a string parameter is only interesting when
its *name* suggests it reaches something dangerous -- a shell, a filesystem
path, an outbound request, a database -- and its *schema* places no bound on
what it can hold. A free-text `nickname` is fine. A free-text `cmd` is a
command injection waiting for a bad day.

Constraining a parameter is also the cheapest real fix in this whole project.
Every finding here has an answer that fits on one line of JSON.

Widen `DANGEROUS_PARAMETER_NAMES` to teach it about your own risky parameters;
widen `CONSTRAINT_KEYWORDS` if you bound them a way this rule does not know.
"""

from typing import Any

from mcplint.core import MEDIUM, Finding, Tool

RULE_ID = "PERMISSIVE_SCHEMA"
SEVERITY = MEDIUM

# Parameter name tokens that suggest the value reaches something with teeth,
# grouped by what it reaches so the finding can say why it matters. The keys
# carry their own article so they read correctly when quoted into a message.
DANGEROUS_PARAMETER_NAMES = {
    "a shell command": (
        "cmd",
        "command",
        "exec",
        "shell",
        "script",
        "run",
        "eval",
        "argv",
        "args",
        "code",
    ),
    "a filesystem path": (
        "path",
        "file",
        "filename",
        "filepath",
        "dir",
        "directory",
        "folder",
        "dest",
        "destination",
        "src",
    ),
    "an outbound request": (
        "url",
        "uri",
        "endpoint",
        "host",
        "hostname",
        "webhook",
        "callback",
        "redirect",
        "proxy",
    ),
    "a database query": (
        "query",
        "sql",
        "statement",
        "where",
        "filter",
    ),
    "template expansion": (
        "template",
        "expression",
        "format",
        "pattern",
    ),
}

# Any one of these on a string schema means somebody thought about the range of
# values this parameter should hold, which is all this rule is asking for.
CONSTRAINT_KEYWORDS = ("enum", "const", "pattern", "maxLength", "format")

# JSON Schema keys whose values are themselves schemas, or collections of them.
# Walking these is what makes the check work on a parameter nested three
# objects deep, which is where the interesting ones tend to hide.
NESTED_SCHEMA_KEYS = ("items", "additionalProperties", "not")
SCHEMA_LIST_KEYS = ("oneOf", "anyOf", "allOf", "prefixItems")
NAMED_SCHEMA_KEYS = ("properties", "$defs", "definitions", "patternProperties")

# A schema deeper than this is either generated or hostile; either way, stop.
MAX_DEPTH = 12


def check_schema_permissiveness(tools: list[Tool]) -> list[Finding]:
    """Report dangerous-sounding string parameters that accept any value."""
    findings: list[Finding] = []
    for tool in tools:
        for path, name, schema in _walk_parameters(tool.input_schema):
            category = _danger_category(name)
            if category is None:
                continue
            if not _is_unconstrained_string(schema):
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity=SEVERITY,
                    tool_name=tool.name,
                    message=(
                        f'parameter "{path}" is an unconstrained free-text string '
                        f"and its name suggests {category}"
                    ),
                    evidence_snippet=_describe(schema),
                    remediation=(
                        f"Bound it: add an {' or '.join(CONSTRAINT_KEYWORDS[:3])} "
                        f'to the schema for "{path}", or a maxLength if the set of '
                        f"valid values genuinely is open. An unbounded parameter is "
                        f"what turns a poisoned description into an executed one."
                    ),
                )
            )
    return findings


def _walk_parameters(schema: Any, path: str = "", depth: int = 0) -> list[tuple[str, str, dict]]:
    """Every named parameter in a schema, including nested ones.

    Yields `(dotted path, parameter name, subschema)`. The dotted path is what
    makes a finding actionable: "config.cmd" tells you where to look,
    "cmd" leaves you searching.
    """
    if depth > MAX_DEPTH or not isinstance(schema, dict):
        return []

    found: list[tuple[str, str, dict]] = []

    for key in NAMED_SCHEMA_KEYS:
        for name, subschema in _items(schema.get(key)):
            child_path = f"{path}.{name}" if path else name
            if isinstance(subschema, dict):
                found.append((child_path, name, subschema))
                found.extend(_walk_parameters(subschema, child_path, depth + 1))

    for key in NESTED_SCHEMA_KEYS:
        found.extend(_walk_parameters(schema.get(key), path, depth + 1))

    for key in SCHEMA_LIST_KEYS:
        for subschema in schema.get(key) or []:
            found.extend(_walk_parameters(subschema, path, depth + 1))

    return found


def _items(value: Any) -> list[tuple[str, Any]]:
    """The `(name, subschema)` pairs of a mapping, or nothing if it is not one."""
    return list(value.items()) if isinstance(value, dict) else []


def _danger_category(name: str) -> str | None:
    """What a parameter name suggests it reaches, if anything.

    Matches on name *tokens* rather than the whole name, so `file_path`,
    `filePath` and `targetUrl` are all caught without listing every spelling.
    """
    tokens = _tokenize(name)
    for category, dangerous in DANGEROUS_PARAMETER_NAMES.items():
        if tokens & set(dangerous):
            return category
    return None


def _tokenize(name: str) -> set[str]:
    """Lowercase word-parts of a parameter name, split on case and separators."""
    spaced = ""
    for index, character in enumerate(name):
        if character in "_-. ":
            spaced += " "
        elif character.isupper() and index > 0 and not name[index - 1].isupper():
            spaced += " " + character
        else:
            spaced += character
    return {part for part in spaced.lower().split() if part}


def _is_unconstrained_string(schema: dict) -> bool:
    """True when a schema accepts a string and says nothing about which ones."""
    if not _accepts_a_string(schema.get("type")):
        return False
    return not any(keyword in schema for keyword in CONSTRAINT_KEYWORDS)


def _accepts_a_string(declared_type: Any) -> bool:
    """True for `"string"` and for unions like `["string", "null"]`."""
    if isinstance(declared_type, list):
        return "string" in declared_type
    return declared_type == "string"


def _describe(schema: dict) -> str:
    """The schema's own keys, so the user can see there is nothing bounding it."""
    keys = ", ".join(sorted(schema)) or "no keys at all"
    return f"schema declares: {keys} -- no {', '.join(CONSTRAINT_KEYWORDS)}"
