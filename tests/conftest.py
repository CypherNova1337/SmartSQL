"""Shared fixtures: a mock vulnerable app behind a simulated WAF.

The mock reproduces the exact conditions SmartSQL is built to handle:

* a **WAF** that inspects URL-*decoded* input and returns 403 for well-known
  attack strings that rely on plain spacing / canonical casing - so naive
  payloads are blocked, but ``space2comment`` / ``randomcase`` tampering slips
  through (charencode does NOT, because the server decodes it first);
* a **vulnerable app** behind it whose ``id`` parameter is error-based *and*
  boolean-based injectable.
"""

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote_plus, urlparse

import pytest

BLOCK_PAGE = "<html><body>Request blocked by Web Application Firewall</body></html>"
RECORD_PAGE = "<html><body>Product #1: Wireless Mouse - in stock</body></html>"
EMPTY_PAGE = "<html><body>No products found.</body></html>"
MYSQL_ERROR = (
    "<html><body>You have an error in your SQL syntax; check the manual that "
    "corresponds to your MySQL server version near ''' at line 1</body></html>"
)

# Case-sensitive strings a signature WAF would flag in decoded input.
_WAF_RULES = ["' OR 1=1", "UNION SELECT", "SLEEP(", "' AND ", " AND SLEEP", "OR 1=2"]


def _blocked(decoded_value: str) -> bool:
    return any(rule in decoded_value for rule in _WAF_RULES)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _reply(self, status: int, body: str):
        # send_response_only avoids http.server's default Server/Date headers,
        # so our synthetic "Server: cloudflare" WAF signature stays clean.
        self.send_response_only(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "cloudflare")  # WAF signature
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        qs = urlparse(self.path).query
        params = parse_qs(qs, keep_blank_values=True)
        value = params.get("id", [""])[0]
        # http.server already percent-decodes; be explicit for '+'.
        decoded = unquote_plus(value) if "%" in value or "+" in value else value

        # --- WAF layer -------------------------------------------------
        if _blocked(decoded):
            self._reply(403, BLOCK_PAGE)
            return

        # --- vulnerable app layer -------------------------------------
        if "'" in decoded:
            if "1=1" in decoded and "1=2" not in decoded:
                self._reply(200, RECORD_PAGE)   # TRUE branch
            elif "1=2" in decoded:
                self._reply(200, EMPTY_PAGE)    # FALSE branch
            else:
                self._reply(200, MYSQL_ERROR)   # broken syntax -> error
            return

        self._reply(200, RECORD_PAGE)


@pytest.fixture()
def mock_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()


# --------------------------------------------------------------------------- #
# A *genuinely* injectable app backed by real SQLite (no WAF), so extraction is
# tested against a real database rather than a hand-rolled simulation.
# --------------------------------------------------------------------------- #
_SCHEMA = """
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, secret TEXT);
INSERT INTO users VALUES (1, 'admin', 's3cr3t-flag');
INSERT INTO users VALUES (2, 'bob',   'hunter2');
INSERT INTO users VALUES (3, 'alice', 'wonderland');
CREATE TABLE products(id INTEGER, title TEXT, price TEXT);
INSERT INTO products VALUES (1, 'Widget', '9.99');
"""


class _SQLiteHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, status: int, body: str):
        self.send_response_only(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        value = qs.get("id", [""])[0]  # parse_qs already URL-decoded this
        # Classic string-concatenation injection: id is unsanitised.
        query = f"SELECT id, name FROM users WHERE id = '{value}'"
        try:
            rows = self.server.db.execute(query).fetchall()
        except Exception as exc:  # leak the SQLite error, like a chatty app
            self._reply(200, f"<html><body>SQL error: {exc}</body></html>")
            return
        if rows:
            names = " ".join(str(r[1]) for r in rows)
            self._reply(200, f"<html><body>Results for product: {names}</body></html>")
        else:
            self._reply(200, "<html><body>No products found.</body></html>")


@pytest.fixture()
def sqlite_app():
    server = HTTPServer(("127.0.0.1", 0), _SQLiteHandler)
    server.db = sqlite3.connect(":memory:", check_same_thread=False)
    server.db.executescript(_SCHEMA)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}"
    server.shutdown()
    server.db.close()
