"""End-to-end extraction tests against a real SQLite-backed vulnerable app."""

from smartsql.engine import Engine, EngineConfig
from smartsql.models import DBMS, Technique
from smartsql.scanner import ExploitConfig, ScanConfig, Scanner
from smartsql.target import Target


def _run(url, techniques, exploit):
    with Engine(EngineConfig(timeout=5.0)) as eng:
        scanner = Scanner(
            eng,
            ScanConfig(techniques=techniques, detect_waf=False),
            on_event=lambda _m: None,
        )
        report = scanner.scan(Target(url))
        assert report.vulnerable, "expected an injection to be found"
        scanner.exploit(report, exploit)
        return report


def test_union_extraction_dumps_users(sqlite_app):
    url = f"{sqlite_app}/product?id=1"
    report = _run(
        url,
        [Technique.UNION, Technique.BOOLEAN, Technique.ERROR],
        ExploitConfig(banner=True, tables=True, dump=True, db="main", table="users"),
    )
    ex = report.exploit
    assert ex is not None
    assert ex.banner.startswith("3.")             # sqlite_version()
    assert "users" in ex.tables.get("main", [])
    assert "products" in ex.tables.get("main", [])

    dump = ex.dumps[0]
    secrets = {row["secret"] for row in dump.rows}
    names = {row["name"] for row in dump.rows}
    assert "s3cr3t-flag" in secrets
    assert {"admin", "bob", "alice"} <= names


def test_boolean_blind_extraction_only(sqlite_app):
    # Force the blind channel by allowing only boolean-based detection.
    url = f"{sqlite_app}/product?id=1"
    report = _run(
        url,
        [Technique.BOOLEAN],
        ExploitConfig(banner=True, columns=True, db="main", table="users"),
    )
    ex = report.exploit
    assert ex.channel == "boolean-blind"
    assert ex.banner.startswith("3.")
    cols = ex.columns.get("main.users", [])
    assert set(cols) == {"id", "name", "secret"}


def test_union_channel_selected_when_available(sqlite_app):
    url = f"{sqlite_app}/product?id=1"
    report = _run(
        url,
        [Technique.UNION, Technique.BOOLEAN],
        ExploitConfig(dump=True, db="main", table="users", cols=["name", "secret"]),
    )
    assert report.exploit.channel == "union"
    dump = report.exploit.dumps[0]
    row = {r["name"]: r["secret"] for r in dump.rows}
    assert row["admin"] == "s3cr3t-flag"


def test_dbms_detected_as_sqlite(sqlite_app):
    url = f"{sqlite_app}/product?id=1"
    report = _run(
        url,
        [Technique.ERROR, Technique.BOOLEAN, Technique.UNION],
        ExploitConfig(banner=True),
    )
    assert report.dbms is DBMS.SQLITE
