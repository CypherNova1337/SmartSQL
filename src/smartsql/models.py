"""Shared data models and enums used across SmartSQL."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class DBMS(enum.Enum):
    """Supported / recognised database management systems."""

    MYSQL = "MySQL"
    POSTGRESQL = "PostgreSQL"
    MSSQL = "Microsoft SQL Server"
    ORACLE = "Oracle"
    SQLITE = "SQLite"
    UNKNOWN = "Unknown"


class Technique(enum.Enum):
    """SQL injection detection/exploitation techniques."""

    BOOLEAN = "boolean-based blind"
    ERROR = "error-based"
    TIME = "time-based blind"
    UNION = "UNION query-based"


class Outcome(enum.Enum):
    """Classified result of a single HTTP exchange, used by the adaptor.

    The self-adaptation controller reacts to these categories rather than to
    raw HTTP status codes, so that new transport behaviours can be mapped onto
    a stable set of reactions.
    """

    OK = "ok"                    # normal response, request went through
    BLOCKED = "blocked"          # WAF / filter rejected the request
    RATE_LIMITED = "rate_limited"  # 429 / throttling signal
    SERVER_ERROR = "server_error"  # 5xx that is not an injectable error
    NETWORK_ERROR = "network_error"  # timeout, reset, DNS, etc.


@dataclass
class InjectionPoint:
    """A single place a payload can be injected into a request."""

    location: str  # e.g. "GET", "POST", "COOKIE", "HEADER"
    name: str      # parameter / header name
    value: str     # original value

    def __str__(self) -> str:
        return f"{self.location}:{self.name}"


@dataclass
class WAFFingerprint:
    """Result of WAF detection."""

    detected: bool = False
    vendor: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        if not self.detected:
            return "no WAF detected"
        vendor = self.vendor or "unknown"
        return f"{vendor} (confidence {self.confidence:.0%})"


@dataclass
class Finding:
    """A confirmed injection finding for a given point/technique."""

    point: InjectionPoint
    technique: Technique
    dbms: DBMS = DBMS.UNKNOWN
    payload: str = ""
    tamper_chain: list[str] = field(default_factory=list)
    notes: str = ""
    # Injection context needed to rebuild valid queries during exploitation:
    # a query becomes  <base><prefix> <expr> <suffix>  e.g. 1' AND (...)-- -
    prefix: str = "'"
    suffix: str = "-- -"
    # Extra technique-specific state (e.g. UNION column count / reflected slot).
    columns: int = 0

    def __str__(self) -> str:
        chain = ", ".join(self.tamper_chain) if self.tamper_chain else "none"
        return (
            f"[{self.technique.value}] {self.point} "
            f"(DBMS={self.dbms.value}, tampers={chain})"
        )
