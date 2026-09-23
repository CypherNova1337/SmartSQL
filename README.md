# SmartSQL

An SQL injection tool that watches how the target blocks it, and changes approach.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square)

## What it does

You find a parameter that looks injectable, point a scanner at it, and the WAF
blocks every payload. So you pick a tamper script, run it again, get blocked
again, pick another, and keep going until something lands or you give up.

That loop is manual, and it's the slow part of the job.

SmartSQL closes it. It sends a payload, watches what the target does with it,
and adapts: blocked, so escalate the obfuscation; throttled, so slow down;
still blocked, so change the request's identity and try a different shape. It
keeps adjusting until something gets through, instead of you choosing a tamper
up front and hoping.

Once an injection is confirmed it does the usual extraction — databases, tables,
columns, rows — through whichever technique worked.

## Why you'd use it

- **Adapts while it runs** rather than needing the right tamper chosen in
  advance.
- **Backs off when throttled** instead of hammering into a block.
- **Four techniques** — boolean, error, time and union — tried as the target
  allows.
- **Rotates request identity** when a target starts recognising it.
- **Extracts data** once a hit is confirmed, so it isn't only a detector.

## Install

```bash
git clone https://github.com/CypherNova1337/SmartSQL
cd SmartSQL
pip install .
```

Needs Python 3.8 or newer.

## Usage

Mark the injection point with `*`:

```bash
smartsql -u 'https://shop.example/item?id=*'
```

It works out what the target does, finds a technique that survives, and tells
you what it found.

**Test a POST body**

```bash
smartsql -u https://shop.example/search --data 'q=*&page=1'
```

**Keep a session**

```bash
smartsql -u 'https://shop.example/account?id=*' -c 'session=abc123'
```

**Pull data once you have a hit**

```bash
smartsql -u 'https://shop.example/item?id=*' --dbs
smartsql -u 'https://shop.example/item?id=*' --tables -D shop
smartsql -u 'https://shop.example/item?id=*' --dump -D shop -T users --max-rows 20
```

**Stay quiet**

```bash
smartsql -u 'https://shop.example/item?id=*' --delay 2 --jitter 3 --random-agent
```

**Watch it adapt**

```bash
smartsql -u 'https://shop.example/item?id=*' -v
```

`-v` streams the adaptation events — what got blocked and what it tried next.
Useful for understanding a WAF rather than just beating it.

**Through Burp**

```bash
smartsql -u 'https://shop.example/item?id=*' --proxy http://127.0.0.1:8080
```

## Options

| Flag | Default | What it does |
|---|---|---|
| `-u` | — | Target URL; `*` marks the injection point |
| `--data` | — | POST body, form-encoded; implies POST |
| `-m` | — | Override the HTTP method |
| `-H` | — | Extra header, `Name: value` |
| `-c` | — | Cookie header |
| `--technique` | `BETU` | Techniques to try: **B**oolean, **E**rror, **T**ime, **U**nion |
| `--time-delay` | — | Delay used by time-based tests |
| `--no-waf` | off | Skip WAF detection |
| `--max-columns` | — | Cap on the UNION column search |
| `--delay` | `0` | Base delay between requests |
| `--jitter` | `0` | Random extra delay, 0 to J |
| `--random-agent` | off | Rotate User-Agent per request |
| `--timeout` | — | Per-request timeout |
| `--proxy` | — | Proxy URL, e.g. Burp |
| `-k` | off | Skip TLS verification |
| `--list-tampers` | — | List tamper scripts and exit |
| `-v` | off | Stream adaptation events |

**Data extraction** (after a confirmed hit): `--banner`, `--current-user`,
`--current-db`, `--dbs`, `--tables`, `--columns`, `--dump`, with `-D`, `-T`,
`-C` and `--max-rows` to narrow it.

## Good to know

- **Time-based is slow and lies on a bad connection.** If the network jitters,
  `--time-delay` needs raising or you'll get false positives from latency.
- **`--dump` reads real data.** On a live system that's someone's personal
  information. Pull the minimum that proves the finding — `--max-rows 5` is
  usually plenty for a report.
- **Adapting means more requests.** It is noisier than a tool that gives up
  early. `--delay` and `--jitter` when that matters.
- **A WAF that blocks everything isn't a clean bill of health.** It means the
  edge held, not that the query is safe. The bug may still be there for someone
  coming from a trusted network.

## Authorised use

Only run this against systems you own or have explicit written permission to
test. Unauthorised SQL injection is a criminal offence in most jurisdictions.

## License

MIT — see [LICENSE](LICENSE).
