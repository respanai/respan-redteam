"""The live-event schema — one typed, serializable class per event the engine emits.

`emit(evt)` (runtime.py) narrates to the campaign sink as `(evt.event, evt.data())`, so the wire
stays `(name: str, payload: dict)` — the SSE stream and the frontend are unchanged. This module is
the single source of truth for every event name and its payload fields; producers construct a class
instead of a bare dict, so the schema is type-checked and typo-proof.

`data()` drops None so optional fields stay absent from the payload (matching the sparse wire)."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import ClassVar


class Event:
    """Base for all events. Subclasses are frozen dataclasses that set the class attribute `event`
    (the wire name) and declare their payload fields."""
    event: ClassVar[str]

    def data(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# --- session lifecycle -------------------------------------------------------
@dataclass(frozen=True)
class SessionStart(Event):
    event = "session.start"
    target: str


@dataclass(frozen=True)
class ReportReady(Event):
    event = "report.ready"
    grade: str
    score: int
    findings: int
    probes: int


# --- recon -------------------------------------------------------------------
@dataclass(frozen=True)
class ReconProbeSent(Event):
    event = "recon.probe.sent"
    name: str
    kind: str
    prompt: str


@dataclass(frozen=True)
class ReconProbeResult(Event):
    event = "recon.probe.result"
    name: str
    snippet: str


@dataclass(frozen=True)
class ReconProfileReady(Event):
    event = "recon.profile.ready"
    profile: dict            # ReconProfile.to_dict(); the profile IS the payload (flat, not nested)

    def data(self) -> dict:
        return dict(self.profile)


# --- orchestration phases ----------------------------------------------------
@dataclass(frozen=True)
class CategoryStart(Event):
    event = "category.start"
    category: str
    phase: str
    goal: str | None = None


@dataclass(frozen=True)
class StrategyStart(Event):
    event = "strategy.start"
    category: str
    strategy: str


@dataclass(frozen=True)
class StrategyError(Event):
    event = "strategy.error"
    strategy: str
    error: str


# --- per-probe attack/response/verdict --------------------------------------
@dataclass(frozen=True)
class AttackAttempt(Event):
    event = "attack.attempt"
    technique: str
    prompt: str


@dataclass(frozen=True)
class TargetResponseEvent(Event):
    event = "target.response"
    snippet: str
    probes_used: int


@dataclass(frozen=True)
class VerdictEvent(Event):
    event = "judge.verdict"
    outcome: str
    severity: str | None = None
    score: float | None = None
    evidence: str | None = None
    # NB: no `technique` — it's already on the preceding attack.attempt for the same probe;
    # consumers pair a verdict to its attempt by position.

    @classmethod
    def from_verdict(cls, verdict, *, evidence=None) -> "VerdictEvent":
        """Project a JudgeVerdict onto the wire event (does the .value extraction once, for all sites)."""
        return cls(outcome=verdict.outcome.value, severity=verdict.severity.value,
                   score=verdict.score, evidence=evidence)


@dataclass(frozen=True)
class FindingDetected(Event):
    event = "finding.critical"
    title: str
    severity: str
