"""SmartSQL command-line interface."""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List, Optional

from . import __version__, tamper
from .engine import EngineConfig
from .models import Technique
from .scanner import ExploitConfig, ScanConfig, build_scanner
from .target import Target

BANNER = r"""
  ____                       _   ____   ___  _
 / ___| _ __ ___   __ _ _ __| |_/ ___| / _ \| |
 \___ \| '_ ` _ \ / _` | '__| __\___ \| | | | |
  ___) | | | | | | (_| | |  | |_ ___) | |_| | |___
 |____/|_| |_| |_|\__,_|_|   \__|____/ \__\_\_____|
       adaptive SQL injection engine  v{ver}
""".format(ver=__version__)

LEGAL = (
    "SmartSQL is for AUTHORISED security testing only. Only run it against "
    "systems you own or have explicit written permission to test. Unauthorised "
    "use may be illegal."
)


def _parse_kv(items: Optional[List[str]], sep: str = ":") -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items or []:
        if sep not in item:
            continue
        k, v = item.split(sep, 1)
        out[k.strip()] = v.strip()
    return out


def _parse_cookies(raw: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _techniques_from_flag(flag: str) -> List[Technique]:
    mapping = {
        "B": Technique.BOOLEAN,
        "E": Technique.ERROR,
        "T": Technique.TIME,
        "U": Technique.UNION,
    }
    chosen = [mapping[c] for c in flag.upper() if c in mapping]
    return chosen or list(Technique)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smartsql",
        description="Adaptive SQL injection engine with self-adapting WAF evasion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=LEGAL,
    )
    p.add_argument("-u", "--url", help="target URL (use * to mark an injection point)")
    p.add_argument("--data", help="POST body (form-encoded); implies POST")
    p.add_argument("-m", "--method", default=None, help="HTTP method override")
    p.add_argument("-H", "--header", action="append", help="extra header 'Name: value'")
    p.add_argument("-c", "--cookie", help="cookie header 'a=1; b=2'")
    p.add_argument(
        "--technique",
        default="BETU",
        help="techniques to try: B(oolean) E(rror) T(ime) U(nion) (default: BETU)",
    )
    p.add_argument("--time-delay", type=int, default=5, help="time-based delay seconds")
    p.add_argument("--no-waf", action="store_true", help="skip WAF detection")
    p.add_argument("--max-columns", type=int, default=12, help="UNION column search cap")

    # exploitation / data extraction
    ex = p.add_argument_group("data extraction (runs after a hit is confirmed)")
    ex.add_argument("--banner", action="store_true", help="retrieve DBMS banner/version")
    ex.add_argument("--current-user", action="store_true", help="retrieve current DB user")
    ex.add_argument("--current-db", action="store_true", help="retrieve current database")
    ex.add_argument("--dbs", action="store_true", help="enumerate databases")
    ex.add_argument("--tables", action="store_true", help="enumerate tables in -D/current db")
    ex.add_argument("--columns", action="store_true", help="enumerate columns of -D -T")
    ex.add_argument("--dump", action="store_true", help="dump rows of -D -T")
    ex.add_argument("-D", "--db", help="database name for --tables/--columns/--dump")
    ex.add_argument("-T", "--table", help="table name for --columns/--dump")
    ex.add_argument("-C", "--cols", help="comma-separated columns for --dump")
    ex.add_argument("--max-rows", type=int, default=200, help="row cap for enumeration/dump")

    # engine / evasion
    p.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--delay", type=float, default=0.0, help="base delay between requests")
    p.add_argument("--jitter", type=float, default=0.0, help="random extra delay [0,J)")
    p.add_argument(
        "--random-agent", action="store_true", help="rotate User-Agent per request"
    )
    p.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")

    # meta
    p.add_argument("--list-tampers", action="store_true", help="list tamper scripts and exit")
    p.add_argument("-v", "--verbose", action="store_true", help="stream adaptation events")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--version", action="version", version=f"smartsql {__version__}")
    return p


def _print_tampers() -> None:
    print("Available tamper scripts:\n")
    for spec in tamper.specs():
        print(f"  [{spec.level}] {spec.name:<24} {spec.description}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_tampers:
        _print_tampers()
        return 0

    if not args.url:
        parser.error("the following argument is required: -u/--url")

    if not args.no_banner:
        print(BANNER)
    print(LEGAL + "\n")

    method = args.method or ("POST" if args.data else "GET")
    target = Target(
        url=args.url,
        method=method,
        data=args.data,
        cookies=_parse_cookies(args.cookie),
        headers=_parse_kv(args.header),
    )

    engine_config = EngineConfig(
        timeout=args.timeout,
        proxy=args.proxy,
        verify_tls=not args.insecure,
        delay=args.delay,
        jitter=args.jitter,
        rotate_user_agent=args.random_agent,
    )
    scan_config = ScanConfig(
        techniques=_techniques_from_flag(args.technique),
        time_delay=args.time_delay,
        detect_waf=not args.no_waf,
        max_columns=args.max_columns,
    )

    def on_event(msg: str) -> None:
        if args.verbose:
            print(f"[*] {msg}")

    exploit_config = ExploitConfig(
        banner=args.banner,
        current_user=args.current_user,
        current_db=args.current_db,
        dbs=args.dbs,
        tables=args.tables,
        columns=args.columns,
        dump=args.dump,
        db=args.db,
        table=args.table,
        cols=[c.strip() for c in args.cols.split(",")] if args.cols else None,
        max_rows=args.max_rows,
    )

    engine, scanner = build_scanner(engine_config, scan_config, on_event)
    try:
        report = scanner.scan(target)
        if report.vulnerable and exploit_config.any:
            scanner.exploit(report, exploit_config)
    except KeyboardInterrupt:
        print("\n[!] interrupted by user")
        return 130
    finally:
        engine.close()

    _print_report(report)
    return 0 if report.vulnerable else 1


def _print_report(report) -> None:
    print("\n" + "=" * 60)
    print("SmartSQL scan report")
    print("=" * 60)
    print(f"target      : {report.target.url}")
    if report.waf is not None:
        print(f"WAF         : {report.waf}")
    print(f"requests    : {report.requests_sent}")
    print(f"DBMS        : {report.dbms.value}")

    if report.findings:
        print(f"\n[+] {len(report.findings)} finding(s):")
        for f in report.findings:
            print(f"    - {f}")
            if f.payload:
                print(f"        payload: {f.payload}")
            if f.notes:
                print(f"        notes  : {f.notes}")
    else:
        print("\n[-] no SQL injection detected")

    if report.exploit is not None:
        _print_exploit(report.exploit)

    if report.adapt_events:
        print(f"\n[*] adaptation log ({len(report.adapt_events)} events):")
        for ev in report.adapt_events:
            print(f"    - {ev}")


def _print_exploit(ex) -> None:
    print(f"\n[+] data extraction (channel: {ex.channel}):")
    if ex.banner:
        print(f"    banner       : {ex.banner}")
    if ex.current_user:
        print(f"    current user : {ex.current_user}")
    if ex.current_db:
        print(f"    current db   : {ex.current_db}")
    if ex.databases:
        print(f"    databases    : {', '.join(ex.databases)}")
    for db, tables in ex.tables.items():
        print(f"    tables[{db}] : {', '.join(tables)}")
    for key, cols in ex.columns.items():
        print(f"    columns[{key}] : {', '.join(cols)}")
    for dump in ex.dumps:
        print(f"\n    dump {dump.db}.{dump.table} ({len(dump.rows)} rows):")
        _print_table(dump.columns, dump.rows)


def _print_table(columns, rows) -> None:
    if not columns:
        return
    widths = {c: len(c) for c in columns}
    for row in rows:
        for c in columns:
            widths[c] = max(widths[c], len(str(row.get(c, ""))))
    widths = {c: min(w, 40) for c, w in widths.items()}

    def fmt(values):
        return " | ".join(str(v)[:widths[c]].ljust(widths[c]) for c, v in zip(columns, values))

    header = fmt(columns)
    print("    " + header)
    print("    " + "-" * len(header))
    for row in rows:
        print("    " + fmt([row.get(c, "") for c in columns]))


if __name__ == "__main__":
    sys.exit(main())
