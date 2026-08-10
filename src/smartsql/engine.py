"""HTTP engine: sends prepared requests and classifies their outcomes.

The engine is deliberately thin but owns three things the adaptor cares about:

* **Identity** - user-agent rotation, custom headers, cookies, proxy.
* **Timing** - a base delay plus optional random jitter between requests.
* **Outcome classification** - mapping transport results onto the stable
  :class:`~smartsql.models.Outcome` categories used by the feedback loop.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from .models import Outcome
from .target import PreparedRequest

# A small pool of realistic desktop user agents used for rotation.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 "
    "Firefox/125.0",
]

# Substrings that strongly indicate a request was blocked by a filter/WAF.
_BLOCK_MARKERS = (
    "access denied",
    "request blocked",
    "forbidden",
    "not acceptable",
    "web application firewall",
    "has been blocked",
    "malicious",
    "security incident",
    "unusual traffic",
)


@dataclass
class Response:
    status_code: int
    text: str
    elapsed: float
    headers: dict
    outcome: Outcome
    error: Optional[str] = None

    @property
    def length(self) -> int:
        return len(self.text)


@dataclass
class EngineConfig:
    timeout: float = 15.0
    proxy: Optional[str] = None
    verify_tls: bool = True
    delay: float = 0.0            # base delay between requests (seconds)
    jitter: float = 0.0          # extra random [0, jitter) seconds
    rotate_user_agent: bool = False
    default_user_agent: str = USER_AGENTS[0]
    max_retries: int = 2


class Engine:
    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig()
        self._client = httpx.Client(
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
            proxy=self.config.proxy,
            follow_redirects=True,
        )
        self.request_count = 0

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    def send(self, req: PreparedRequest) -> Response:
        """Send a request, honouring timing and identity policy."""
        self._pace()
        headers = self._identity_headers(req.headers)

        attempt = 0
        last_error: Optional[str] = None
        while attempt <= self.config.max_retries:
            attempt += 1
            try:
                start = time.perf_counter()
                resp = self._client.request(
                    req.method,
                    req.url,
                    data=req.data if req.method != "GET" else None,
                    cookies=req.cookies or None,
                    headers=headers,
                )
                elapsed = time.perf_counter() - start
                self.request_count += 1
                return Response(
                    status_code=resp.status_code,
                    text=resp.text,
                    elapsed=elapsed,
                    headers=dict(resp.headers),
                    outcome=self._classify(resp.status_code, resp.text),
                )
            except (httpx.TimeoutException,) as exc:
                last_error = f"timeout: {exc}"
            except (httpx.TransportError,) as exc:
                last_error = f"transport: {exc}"
            # brief backoff before retrying network failures
            time.sleep(min(2 ** attempt * 0.25, 4.0))

        return Response(
            status_code=0,
            text="",
            elapsed=0.0,
            headers={},
            outcome=Outcome.NETWORK_ERROR,
            error=last_error,
        )

    # ------------------------------------------------------------------ #
    def _pace(self) -> None:
        wait = self.config.delay
        if self.config.jitter > 0:
            wait += random.uniform(0, self.config.jitter)
        if wait > 0:
            time.sleep(wait)

    def _identity_headers(self, extra: dict) -> dict:
        headers = {}
        if self.config.rotate_user_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        else:
            headers["User-Agent"] = self.config.default_user_agent
        headers.update(extra or {})
        return headers

    @staticmethod
    def _classify(status: int, body: str) -> Outcome:
        if status == 429:
            return Outcome.RATE_LIMITED
        if status in (403, 406, 419, 451):
            return Outcome.BLOCKED
        lowered = body.lower()
        if status >= 500:
            # 5xx frequently *is* the injectable error, so only treat as a
            # hard server error when the body doesn't look like a DB message.
            return Outcome.SERVER_ERROR
        if any(marker in lowered for marker in _BLOCK_MARKERS):
            return Outcome.BLOCKED
        return Outcome.OK
