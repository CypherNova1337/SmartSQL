"""The self-adaptation controller - SmartSQL's core differentiator.

Where classic tools apply a fixed tamper script chosen up front, SmartSQL runs
a feedback loop. For every payload it:

1. picks the tamper chain with the best learned score,
2. sends the request through the engine,
3. classifies the outcome, and
4. *reacts*:
   * ``BLOCKED``      -> penalise the chain, escalate to a stronger chain,
                        and (once) rotate request identity.
   * ``RATE_LIMITED`` -> increase inter-request delay (multiplicative backoff).
   * ``NETWORK_ERROR``-> back off timing, keep the chain.
   * ``OK``           -> reward the chain.

Over a scan the controller converges on whichever encoding reliably slips past
the target's filter, and keeps the request rate under the target's tolerance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import tamper
from .engine import Engine, Response
from .models import Outcome
from .target import InjectionPoint, Target

# Escalation ladder: ordered candidate tamper chains, weakest first. The
# controller starts empty (no tampering) and climbs as it meets resistance.
DEFAULT_LADDER: List[List[str]] = [
    [],
    ["randomcase"],
    ["space2comment"],
    ["randomcase", "space2comment"],
    ["charencode"],
    ["randomcase", "space2randomblank"],
    ["equaltolike", "randomcase"],
    ["randomcomments", "randomcase"],
    ["versionedmorekeywords"],
    ["space2hash", "randomcase"],
    ["charunicodeencode"],
    ["doubleencode"],
]


@dataclass
class ChainStats:
    attempts: int = 0
    passed: int = 0     # not blocked
    blocked: int = 0

    @property
    def score(self) -> float:
        # Laplace-smoothed pass rate so untried chains stay explorable.
        return (self.passed + 1) / (self.attempts + 2)


@dataclass
class AdaptState:
    delay: float = 0.0
    jitter: float = 0.0
    identity_rotated: bool = False
    escalation: int = 0  # index into the ladder we've climbed to
    events: List[str] = field(default_factory=list)


class AdaptiveController:
    def __init__(
        self,
        engine: Engine,
        ladder: Optional[List[List[str]]] = None,
        max_delay: float = 8.0,
        on_event: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.engine = engine
        self.ladder = ladder or list(DEFAULT_LADDER)
        self.max_delay = max_delay
        self.on_event = on_event
        self.stats: dict[tuple[str, ...], ChainStats] = {}
        self.state = AdaptState(
            delay=engine.config.delay,
            jitter=engine.config.jitter,
        )

    # ------------------------------------------------------------------ #
    def _log(self, msg: str) -> None:
        self.state.events.append(msg)
        if self.on_event:
            self.on_event(msg)

    def _stats(self, chain: List[str]) -> ChainStats:
        key = tuple(chain)
        return self.stats.setdefault(key, ChainStats())

    def best_chain(self) -> List[str]:
        """Highest-scoring chain seen so far, or the first ladder rung."""
        if not self.stats:
            return list(self.ladder[0])
        key = max(self.stats, key=lambda k: self.stats[k].score)
        return list(key)

    # ------------------------------------------------------------------ #
    def send(
        self,
        target: Target,
        point: InjectionPoint,
        payload: str,
        max_escalations: int = 6,
    ) -> "AdaptiveResult":
        """Send ``payload`` at ``point``, adapting until it isn't blocked.

        Returns the first non-blocked :class:`Response` (or the last blocked
        one if every escalation is exhausted), together with the chain used.
        """
        rung = self.state.escalation
        tried: List[List[str]] = []

        for _ in range(max_escalations + 1):
            chain = self._chain_for_rung(rung)
            tried.append(chain)
            stats = self._stats(chain)

            tampered = tamper.apply_chain(payload, chain)
            req = target.build(point, tampered)
            resp = self.engine.send(req)
            stats.attempts += 1

            reaction = self._react(resp, chain)
            if reaction != "escalate":
                stats.passed += 1
                # A rung that works becomes the new baseline for this scan.
                self.state.escalation = min(rung, self.state.escalation) \
                    if resp.outcome == Outcome.OK else self.state.escalation
                return AdaptiveResult(resp, chain, tampered, tried)

            stats.blocked += 1
            rung = min(rung + 1, len(self.ladder) - 1)
            self.state.escalation = rung

        return AdaptiveResult(resp, chain, tampered, tried)

    # ------------------------------------------------------------------ #
    def _chain_for_rung(self, rung: int) -> List[str]:
        rung = max(0, min(rung, len(self.ladder) - 1))
        return list(self.ladder[rung])

    def _react(self, resp: Response, chain: List[str]) -> str:
        """Update engine/controller state; return 'escalate' or 'accept'."""
        outcome = resp.outcome

        if outcome == Outcome.BLOCKED:
            self._log(
                f"blocked (chain={chain or 'none'}) -> escalating tamper"
            )
            if not self.state.identity_rotated:
                self.engine.config.rotate_user_agent = True
                self.state.identity_rotated = True
                self._log("rotating request identity (User-Agent)")
            return "escalate"

        if outcome == Outcome.RATE_LIMITED:
            self._backoff(reason="rate-limited (429)")
            return "escalate"

        if outcome == Outcome.NETWORK_ERROR:
            self._backoff(reason=f"network error: {resp.error}")
            return "accept"  # nothing to gain from re-tampering a dead socket

        return "accept"

    def _backoff(self, reason: str) -> None:
        old = self.engine.config.delay
        new = min(max(old * 2, 0.5), self.max_delay)
        self.engine.config.delay = new
        self.engine.config.jitter = max(self.engine.config.jitter, 0.3)
        self.state.delay = new
        self.state.jitter = self.engine.config.jitter
        self._log(f"{reason} -> delay {old:.2f}s -> {new:.2f}s")


@dataclass
class AdaptiveResult:
    response: Response
    chain: List[str]
    payload_sent: str
    chains_tried: List[List[str]]

    @property
    def got_through(self) -> bool:
        return self.response.outcome == Outcome.OK
