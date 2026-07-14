"""Campaign-scoped ambient context (budget, usage, sink, target, profile) held in a contextvar so concurrent asyncio campaigns stay isolated; budget/usage are consumed only at the leaves."""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .events import AttackAttempt, TargetResponseEvent
from .models import EventSink, ReconProfile

if TYPE_CHECKING:
    from .config import BudgetConfig, EngineConfig
    from .events import Event


class BudgetExhausted(RuntimeError):
    """Raised at the leaf (send) when the probe cap is reached."""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens


@dataclass
class Budget:
    """Counter of TARGET probes. `consume()` reserves a slot and raises at the cap."""
    max_probes: int
    sent: int = 0

    def remaining(self) -> int:
        return max(0, self.max_probes - self.sent)

    def can_send(self, n: int = 1) -> bool:
        return self.sent + n <= self.max_probes

    def consume(self, n: int = 1) -> None:
        if not self.can_send(n):
            raise BudgetExhausted()
        self.sent += n



@dataclass
class CampaignRuntime:
    """All campaign-scoped state."""
    budget: Budget
    config: "EngineConfig"
    usage: Usage = field(default_factory=Usage)
    sink: EventSink | None = None
    target: Any = None                      # the raw session Target (target.open() -> Chat)
    profile: ReconProfile = field(default_factory=ReconProfile)   # empty until set_profile()
    canary: Any = None


_ctx: contextvars.ContextVar[CampaignRuntime | None] = contextvars.ContextVar("campaign", default=None)


def _cur() -> CampaignRuntime:
    c = _ctx.get()
    if c is None:
        raise RuntimeError("no active campaign_scope(); wrap the campaign in `with campaign_scope(...)`")
    return c


@contextmanager
def campaign_scope(
    config: "EngineConfig | BudgetConfig",
    target: Any = None,
    sink: EventSink | None = None,
):
    """Enter a campaign: set up ambient state for its duration. Uses contextvars so nested
    tasks/coroutines each see this context; on exit the previous context is restored."""
    from .config import EngineConfig

    if not isinstance(config, EngineConfig):
        config = EngineConfig(budget=config)
    token = _ctx.set(
        CampaignRuntime(
            Budget(config.budget.max_target_probes),
            config=config,
            sink=sink,
            target=target,
        )
    )
    try:
        yield _ctx.get()
    finally:
        _ctx.reset(token)


# --- ambient accessors (reads, not threading) --------------------------------
def current_budget() -> Budget:
    return _cur().budget


def current_usage() -> Usage:
    return _cur().usage


def current_cfg() -> "BudgetConfig":
    return _cur().config.budget


def current_config() -> "EngineConfig":
    current = _ctx.get()
    if current is not None:
        return current.config
    from .config import DEFAULT_ENGINE_CONFIG

    return DEFAULT_ENGINE_CONFIG


def current_profile() -> "ReconProfile":
    return _cur().profile


def set_profile(profile: "ReconProfile") -> None:
    _cur().profile = profile


def current_canary() -> Any:
    return _cur().canary


def set_canary(canary: Any) -> None:
    _cur().canary = canary


def budget_remaining() -> int:
    return _cur().budget.remaining()


def budget_can_send(n: int = 1) -> bool:
    return _cur().budget.can_send(n)


def record_usage(u: Usage) -> None:
    """Best-effort: accumulate token usage if inside a campaign; no-op otherwise (so
    llm.complete works in isolated tests/targets without a scope)."""
    c = _ctx.get()
    if c is not None:
        c.usage.add(u)


def emit(evt: "Event") -> None:
    """Narrate a typed event to the ambient sink (no-op if none). The sink still receives the
    wire form `(name, payload)` — see events.py."""
    c = _ctx.get()
    if c is not None and c.sink is not None:
        c.sink(evt.event, evt.data())


class ScopedChat:
    """A live Chat wrapped in the ambient campaign: every send is the single budget leaf
    (consumes one probe, raises BudgetExhausted at the cap) and narrates to the sink. Strategies
    hold one of these per attack conversation via open_chat()."""

    def __init__(self, inner):
        self._inner = inner

    def send(self, user_message: str, technique: str = "", narrate: bool = True) -> str:
        ctx = _cur()
        if not ctx.budget.can_send():
            raise BudgetExhausted()
        if narrate:
            emit(AttackAttempt(technique=technique, prompt=user_message[:400]))
        ctx.budget.consume()                      # reserve the probe (single consumption point)
        try:
            resp = self._inner.send(user_message)
        except BudgetExhausted:
            raise
        except Exception as exc:  # noqa: BLE001
            resp = f"[target error: {exc}]"
        # Defence in depth: a Chat.send should return a str, but a user adapter might hand back None;
        # coerce so the reply is always safe to slice/judge. (The sandbox chat coerces at its layer
        # too, keeping None out of the stored transcript.)
        if not isinstance(resp, str):
            resp = "" if resp is None else str(resp)
        if narrate:
            emit(TargetResponseEvent(snippet=resp[:400], probes_used=ctx.budget.sent))
        return resp

    def transcript(self) -> list[dict]:
        return self._inner.transcript()


def open_chat() -> ScopedChat:
    """Open a fresh, isolated conversation on the ambient campaign target (one per attack)."""
    return ScopedChat(_cur().target.open())


def probe(user_message: str, technique: str = "") -> str:
    """Single-shot convenience: open a fresh conversation and send one user message."""
    return open_chat().send(user_message, technique=technique)
