"""Target modelling: parse a URL / request into injectable points.

A ``Target`` captures everything needed to reproduce a request and to build
mutated variants where a single injection point carries a payload. Injection
points can live in the query string, the POST body, cookies, or headers.

The special marker ``*`` in a URL, body, cookie or header value pins the
injection point explicitly (sqlmap-compatible behaviour). If no marker is
present, every GET/POST parameter is treated as a candidate point.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .models import InjectionPoint

MARKER = "*"


@dataclass
class Target:
    url: str
    method: str = "GET"
    data: Optional[str] = None  # raw POST body (form-encoded)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.method = self.method.upper()

    # ------------------------------------------------------------------ #
    # Injection point discovery
    # ------------------------------------------------------------------ #
    def injection_points(self) -> List[InjectionPoint]:
        """Return all candidate injection points.

        If explicit ``*`` markers exist, only those are returned. Otherwise all
        query/body params (and marked cookies/headers) become candidates.
        """
        marked = self._marked_points()
        if marked:
            return marked

        points: List[InjectionPoint] = []
        for name, value in self._query_params():
            points.append(InjectionPoint("GET", name, value))
        if self.method == "POST" and self.data:
            for name, value in parse_qsl(self.data, keep_blank_values=True):
                points.append(InjectionPoint("POST", name, value))
        return points

    def _marked_points(self) -> List[InjectionPoint]:
        points: List[InjectionPoint] = []
        for name, value in self._query_params():
            if MARKER in value:
                points.append(InjectionPoint("GET", name, value))
        if self.data:
            for name, value in parse_qsl(self.data, keep_blank_values=True):
                if MARKER in value:
                    points.append(InjectionPoint("POST", name, value))
        for name, value in self.cookies.items():
            if MARKER in value:
                points.append(InjectionPoint("COOKIE", name, value))
        for name, value in self.headers.items():
            if MARKER in value:
                points.append(InjectionPoint("HEADER", name, value))
        return points

    def _query_params(self) -> List[tuple[str, str]]:
        parsed = urlparse(self.url)
        return parse_qsl(parsed.query, keep_blank_values=True)

    # ------------------------------------------------------------------ #
    # Request building
    # ------------------------------------------------------------------ #
    def build(self, point: InjectionPoint, payload: str) -> "PreparedRequest":
        """Produce a concrete request with ``payload`` at ``point``.

        The injected value is ``base + payload`` where ``base`` is the original
        parameter value with any marker removed - this preserves legitimate
        context (e.g. ``id=1`` becoming ``id=1' AND 1=1``).
        """
        base = point.value.replace(MARKER, "")
        injected = base + payload

        url = self.url
        data = self.data
        cookies = dict(self.cookies)
        headers = dict(self.headers)

        if point.location == "GET":
            url = self._replace_query(point.name, injected)
        elif point.location == "POST":
            data = self._replace_body(point.name, injected)
        elif point.location == "COOKIE":
            cookies[point.name] = injected
        elif point.location == "HEADER":
            headers[point.name] = injected

        return PreparedRequest(
            method=self.method,
            url=url,
            data=data,
            cookies=cookies,
            headers=headers,
        )

    def baseline(self) -> "PreparedRequest":
        """The unmodified request, with markers stripped."""
        url = self.url.replace(MARKER, "")
        data = self.data.replace(MARKER, "") if self.data else None
        cookies = {k: v.replace(MARKER, "") for k, v in self.cookies.items()}
        headers = {k: v.replace(MARKER, "") for k, v in self.headers.items()}
        return PreparedRequest(self.method, url, data, cookies, headers)

    def _replace_query(self, name: str, value: str) -> str:
        parsed = urlparse(self.url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        new_params = [(k, value if k == name else v) for k, v in params]
        new_query = urlencode(new_params, safe="%*()',/")
        return urlunparse(parsed._replace(query=new_query))

    def _replace_body(self, name: str, value: str) -> str:
        params = parse_qsl(self.data or "", keep_blank_values=True)
        new_params = [(k, value if k == name else v) for k, v in params]
        return urlencode(new_params, safe="%*()',/")


@dataclass
class PreparedRequest:
    method: str
    url: str
    data: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    def clone(self) -> "PreparedRequest":
        return copy.deepcopy(self)
