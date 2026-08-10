"""Fast unit tests for the pure components."""

from smartsql import dbms, tamper
from smartsql.models import DBMS, Outcome
from smartsql.engine import Engine
from smartsql.target import Target


def test_tamper_registry_populated():
    names = tamper.all_names()
    assert "space2comment" in names
    assert "randomcase" in names
    assert len(names) >= 10


def test_space2comment():
    assert tamper.get("space2comment")("a b c") == "a/**/b/**/c"


def test_apply_chain_is_composed_left_to_right():
    out = tamper.apply_chain("A B", ["space2comment", "charencode"])
    # spaces became /**/, then everything got %-encoded
    assert out.startswith("%41")
    assert "%2f%2a%2a%2f" in out  # encoded /**/


def test_charencode_roundtrips_conceptually():
    enc = tamper.get("charencode")("'")
    assert enc == "%27"


def test_target_discovers_query_params():
    t = Target("http://h/p?a=1&b=2")
    pts = {str(p) for p in t.injection_points()}
    assert pts == {"GET:a", "GET:b"}


def test_target_respects_explicit_marker():
    t = Target("http://h/p?a=1*&b=2")
    pts = t.injection_points()
    assert len(pts) == 1 and pts[0].name == "a"


def test_target_build_appends_payload_to_base():
    t = Target("http://h/p?id=1")
    req = t.build(t.injection_points()[0], "' AND 1=1-- -")
    assert "id=1" in req.url and "AND" in req.url


def test_post_body_points():
    t = Target("http://h/p", method="POST", data="user=x&pass=y")
    pts = {str(p) for p in t.injection_points()}
    assert pts == {"POST:user", "POST:pass"}


def test_dbms_error_fingerprint():
    assert dbms.fingerprint_from_error(
        "You have an error in your SQL syntax"
    ) is DBMS.MYSQL
    assert dbms.fingerprint_from_error("ORA-00933: bad") is DBMS.ORACLE
    assert dbms.fingerprint_from_error("nothing here") is DBMS.UNKNOWN


def test_time_payloads_specific_vs_unknown():
    assert all("SLEEP" in p for p in dbms.time_payloads(DBMS.MYSQL, 5))
    assert len(dbms.time_payloads(DBMS.UNKNOWN, 5)) > 3


def test_engine_classify():
    assert Engine._classify(429, "") is Outcome.RATE_LIMITED
    assert Engine._classify(403, "") is Outcome.BLOCKED
    assert Engine._classify(200, "access denied") is Outcome.BLOCKED
    assert Engine._classify(200, "hello") is Outcome.OK
    assert Engine._classify(500, "boom") is Outcome.SERVER_ERROR
