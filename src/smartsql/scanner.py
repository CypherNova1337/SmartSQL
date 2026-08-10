"""Scan orchestration: WAF detect -> per-point technique sweep -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .adaptive import AdaptiveController
from .engine import Engine, EngineConfig
from .extract import DumpResult, Extractor
from .models import DBMS, Finding, InjectionPoint, Technique, WAFFingerprint
from .target import Target
from .techniques import Detector
from .waf import WAFDetector


@dataclass
class ScanConfig:
    techniques: List[Technique] = field(
        default_factory=lambda: list(Technique)
    )
    time_delay: int = 5
    detect_waf: bool = True
    max_columns: int = 12


@dataclass
class ExploitConfig:
    """What to extract once an injection is confirmed."""

    banner: bool = False
    current_user: bool = False
    current_db: bool = False
    dbs: bool = False
    tables: bool = False
    columns: bool = False
    dump: bool = False
    db: Optional[str] = None
    table: Optional[str] = None
    cols: Optional[List[str]] = None
    max_rows: int = 200

    @property
    def any(self) -> bool:
        return any(
            (self.banner, self.current_user, self.current_db, self.dbs,
             self.tables, self.columns, self.dump)
        )


@dataclass
class ExploitResult:
    channel: str = ""
    banner: Optional[str] = None
    current_user: Optional[str] = None
    current_db: Optional[str] = None
    databases: List[str] = field(default_factory=list)
    tables: Dict[str, List[str]] = field(default_factory=dict)
    columns: Dict[str, List[str]] = field(default_factory=dict)
    dumps: List[DumpResult] = field(default_factory=list)


@dataclass
class ScanReport:
    target: Target
    waf: Optional[WAFFingerprint] = None
    findings: List[Finding] = field(default_factory=list)
    dbms: DBMS = DBMS.UNKNOWN
    requests_sent: int = 0
    adapt_events: List[str] = field(default_factory=list)
    exploit: Optional[ExploitResult] = None

    @property
    def vulnerable(self) -> bool:
        return bool(self.findings)

    def findings_by_point(self) -> Dict[str, List[Finding]]:
        grouped: Dict[str, List[Finding]] = {}
        for f in self.findings:
            grouped.setdefault(str(f.point), []).append(f)
        return grouped


class Scanner:
    def __init__(
        self,
        engine: Engine,
        scan_config: Optional[ScanConfig] = None,
        on_event: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.engine = engine
        self.config = scan_config or ScanConfig()
        self.on_event = on_event or (lambda _msg: None)
        self.controller = AdaptiveController(engine, on_event=self.on_event)

    def scan(self, target: Target) -> ScanReport:
        report = ScanReport(target=target)

        if self.config.detect_waf:
            self.on_event("detecting WAF ...")
            report.waf = WAFDetector(self.engine).detect(target)
            self.on_event(f"WAF: {report.waf}")

        points = target.injection_points()
        if not points:
            self.on_event("no injection points found")
            report.requests_sent = self.engine.request_count
            return report

        detector = Detector(self.controller, target)

        for point in points:
            self.on_event(f"testing {point} ...")
            self._sweep_point(detector, point, report)

        # Consolidate DBMS across findings.
        for f in report.findings:
            if f.dbms is not DBMS.UNKNOWN:
                report.dbms = f.dbms
                break

        report.requests_sent = self.engine.request_count
        report.adapt_events = list(self.controller.state.events)
        return report

    # ------------------------------------------------------------------ #
    def exploit(self, report: ScanReport, cfg: ExploitConfig) -> Optional[ExploitResult]:
        """Extract data through the strongest injection in ``report``."""
        if not report.vulnerable or not cfg.any:
            return None

        grouped = report.findings_by_point()
        point_key, findings = next(iter(grouped.items()))
        point = findings[0].point
        self.on_event(f"exploiting {point_key} ...")

        extractor = Extractor(
            self.controller,
            report.target,
            point,
            findings,
            dbms=report.dbms,
            delay=self.config.time_delay,
            max_rows=cfg.max_rows,
            on_event=self.on_event,
        )
        if not extractor.prepare():
            report.requests_sent = self.engine.request_count
            return None

        result = ExploitResult(channel=extractor.channel.name)
        if cfg.banner:
            result.banner = extractor.banner()
            self.on_event(f"  banner: {result.banner}")
        if cfg.current_user:
            result.current_user = extractor.current_user()
            self.on_event(f"  current user: {result.current_user}")
        if cfg.current_db:
            result.current_db = extractor.current_db()
            self.on_event(f"  current db: {result.current_db}")

        # Resolve the working database for table/column/dump operations.
        db = cfg.db or (extractor.current_db() if extractor.dialect.current_db_expr else None)

        if cfg.dbs:
            result.databases = extractor.databases()
            self.on_event(f"  databases: {result.databases}")
        if cfg.tables and db:
            result.tables[db] = extractor.tables(db)
            self.on_event(f"  tables[{db}]: {result.tables[db]}")
        if cfg.columns and db and cfg.table:
            key = f"{db}.{cfg.table}"
            result.columns[key] = extractor.columns(db, cfg.table)
            self.on_event(f"  columns[{key}]: {result.columns[key]}")
        if cfg.dump and db and cfg.table:
            dump = extractor.dump(db, cfg.table, cfg.cols)
            result.dumps.append(dump)
            self.on_event(f"  dumped {len(dump.rows)} row(s) from {db}.{cfg.table}")

        report.exploit = result
        report.requests_sent = self.engine.request_count
        report.adapt_events = list(self.controller.state.events)
        return result

    def _sweep_point(self, detector: Detector, point, report: ScanReport) -> None:
        techniques = self.config.techniques
        dbms_hint = report.dbms

        if Technique.ERROR in techniques:
            r = detector.error_based(point)
            self.on_event(f"  error-based: {r.detail}")
            if r.finding:
                report.findings.append(r.finding)
                dbms_hint = r.finding.dbms

        if Technique.BOOLEAN in techniques:
            r = detector.boolean_based(point)
            self.on_event(f"  boolean-based: {r.detail}")
            if r.finding:
                report.findings.append(r.finding)

        if Technique.TIME in techniques:
            r = detector.time_based(point, self.config.time_delay, dbms_hint)
            self.on_event(f"  time-based: {r.detail}")
            if r.finding:
                report.findings.append(r.finding)
                dbms_hint = r.finding.dbms

        if Technique.UNION in techniques:
            r = detector.union_based(point, self.config.max_columns)
            self.on_event(f"  union-based: {r.detail}")
            if r.finding:
                report.findings.append(r.finding)


def build_scanner(
    engine_config: Optional[EngineConfig] = None,
    scan_config: Optional[ScanConfig] = None,
    on_event: Optional[Callable[[str], None]] = None,
) -> tuple[Engine, Scanner]:
    engine = Engine(engine_config)
    scanner = Scanner(engine, scan_config, on_event)
    return engine, scanner
