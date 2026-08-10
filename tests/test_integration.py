"""End-to-end tests exercising WAF detection + adaptation + detection."""

from smartsql.engine import Engine, EngineConfig
from smartsql.models import DBMS, Outcome, Technique
from smartsql.scanner import ScanConfig, Scanner
from smartsql.target import Target
from smartsql.waf import WAFDetector


def _engine():
    return Engine(EngineConfig(timeout=5.0))


def test_waf_is_detected(mock_server):
    target = Target(f"{mock_server}/item?id=1")
    with _engine() as eng:
        fp = WAFDetector(eng).detect(target)
    assert fp.detected
    # cloudflare Server header signature should be picked up
    assert fp.vendor == "Cloudflare"


def test_naive_payload_is_blocked_but_tampered_gets_through(mock_server):
    target = Target(f"{mock_server}/item?id=1")
    with _engine() as eng:
        # naive: raw "' OR 1=1" is on the WAF blocklist
        raw = eng.send(target.build(target.injection_points()[0], "' OR 1=1-- -"))
        assert raw.outcome == Outcome.BLOCKED
        # space2comment breaks up the "' OR 1=1" signature deterministically
        from smartsql import tamper

        tampered_payload = tamper.apply_chain("' OR 1=1-- -", ["space2comment"])
        tampered = eng.send(
            target.build(target.injection_points()[0], tampered_payload)
        )
        assert tampered.outcome != Outcome.BLOCKED


def test_scan_finds_injection_and_adapts(mock_server):
    target = Target(f"{mock_server}/item?id=1")
    events = []
    with _engine() as eng:
        scanner = Scanner(
            eng,
            ScanConfig(
                techniques=[Technique.ERROR, Technique.BOOLEAN],
                detect_waf=True,
            ),
            on_event=events.append,
        )
        report = scanner.scan(target)

    assert report.vulnerable
    techniques_found = {f.technique for f in report.findings}
    assert Technique.ERROR in techniques_found
    assert report.dbms is DBMS.MYSQL
    # The adaptation loop must have reacted to at least one block/escalation.
    assert any("escalat" in e or "blocked" in e for e in report.adapt_events)


def test_clean_target_reports_not_vulnerable():
    # A target that never returns errors/differentials: use a non-injectable
    # value space by pointing at a bad host is unreliable; instead assert the
    # boolean logic needs a real differential. Here we just verify the report
    # shape for an empty injection-point set.
    target = Target("http://127.0.0.1:1/nope")
    with _engine() as eng:
        scanner = Scanner(eng, ScanConfig(detect_waf=False))
        report = scanner.scan(target)
    assert not report.vulnerable
