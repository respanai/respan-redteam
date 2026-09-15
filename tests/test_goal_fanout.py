"""Guards for advancing several goals at once within a stage.

Goals in a stage are independent — the stage's goal list is computed once, a
goal seeds only from its OWN probes in earlier stages, and `solved` only affects
the NEXT stage — so a stage can advance several at a time. Three things that
were free while the loop was sequential now have to be enforced:

  - **the sink stays single-threaded.** It is a caller-supplied callable and the
    shipped ones are not thread-safe (the CLI dashboard mutates plain counters
    and drives a rich Live display), so `emit` must serialise on their behalf.
  - **severity order still decides who gets budget.** Goals compete for one
    probe budget; running the whole stage at once would let a LOW goal spend
    what a CRITICAL one needed. The fan-out is a WINDOW over the severity-sorted
    list, so that only happens between goals of comparable severity.
  - **the report does not depend on scheduling.** Probes and findings are merged
    in goal order, not completion order.
"""

import threading
import time

import pytest

from respan_redteam import model_client
from respan_redteam.campaign import run_campaign
from respan_redteam.config import BudgetConfig, EngineConfig
from respan_redteam.model_client import LLMResult
from respan_redteam.runtime import Usage

LATENCY_SECONDS = 0.01
# The LLM01 goal is judged deterministically: success is the target echoing this
# exact marker. Leaking it gives the campaign real findings to compare, so the
# determinism assertions below are not comparing two empty lists.
CANARY = "RESPAN-HIJACK-9F3A"


class _Chat:
    def __init__(self, target):
        self._target = target

    def send(self, message):
        with self._target.lock:
            self._target.sends += 1
            self._target.concurrent += 1
            self._target.peak_concurrent = max(
                self._target.peak_concurrent, self._target.concurrent
            )
        try:
            time.sleep(LATENCY_SECONDS)
            if CANARY in message:
                return CANARY          # deterministic breach on the injection goal
            return "I cannot help with that."
        finally:
            with self._target.lock:
                self._target.concurrent -= 1

    def transcript(self):
        return []


class _Target:
    label = "fake"

    def __init__(self):
        self.sends = 0
        self.concurrent = 0
        self.peak_concurrent = 0
        self.lock = threading.Lock()

    def open(self):
        return _Chat(self)


class _RecordingSink:
    """A deliberately NON-thread-safe sink, like the shipped ones."""

    def __init__(self):
        self.events = []
        self.payloads = []
        self.max_concurrent = 0
        self._concurrent = 0
        self._guard = threading.Lock()

    def __call__(self, event, data):
        with self._guard:
            self._concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self._concurrent)
        # A real sink does unguarded work here; hold the window open so any
        # genuine overlap is observed rather than missed.
        time.sleep(0.0005)
        self.events.append(event)
        self.payloads.append((event, data))
        with self._guard:
            self._concurrent -= 1


@pytest.fixture(autouse=True)
def _faked_llm(monkeypatch):
    def complete(model_id, user=None, system=None, **kwargs):
        time.sleep(LATENCY_SECONDS)
        return LLMResult(text="attack prompt", usage=Usage())

    def complete_json(model_id, user=None, system=None, **kwargs):
        time.sleep(LATENCY_SECONDS)
        if "candidate attack prompts" in (user or ""):
            return ["a", "b", "c"]
        if "RECON PROBE RESPONSES" in (user or ""):
            return {"target_type": "llm", "guardrail_strength": "low"}
        if "worth grading" in (system or ""):
            return {"verdict": "refused", "reason": "refused"}
        return {
            "specificity": 1, "actionability": 1, "evidence_span": "",
            "severity": "low", "rationale": "refused",
        }

    monkeypatch.setattr(model_client, "complete", complete)
    monkeypatch.setattr(model_client, "complete_json", complete_json)
    import respan_redteam.judge as judge_module

    monkeypatch.setattr(judge_module, "model_client", model_client)


def _campaign(*, max_probes=40, goal_concurrency=3, recon_concurrency=9):
    target = _Target()
    sink = _RecordingSink()
    config = EngineConfig(
        budget=BudgetConfig(
            max_target_probes=max_probes,
            goal_concurrency=goal_concurrency,
            recon_concurrency=recon_concurrency,
        )
    )
    started = time.perf_counter()
    result = run_campaign(target, config=config, sink=sink)
    return result, target, sink, time.perf_counter() - started


def test_the_sink_is_never_called_from_two_threads_at_once():
    """The engine owns this guarantee; sinks are caller-supplied and unsynchronised."""
    _, _, sink, _ = _campaign()

    assert sink.events, "campaign emitted nothing"
    assert sink.max_concurrent == 1, (
        f"sink was called {sink.max_concurrent} times concurrently"
    )


def test_goals_actually_advance_concurrently():
    _, target, _, _ = _campaign()

    assert target.peak_concurrent > 1, "stage advanced goals one at a time"


@pytest.mark.parametrize("max_probes", [1, 5, 12, 40])
def test_the_probe_budget_is_never_overshot(max_probes):
    result, target, _, _ = _campaign(max_probes=max_probes)

    assert target.sends <= max_probes
    assert result.probes_sent <= max_probes


def test_the_campaign_finds_something_to_compare():
    """Sanity check for the determinism tests below: they must not compare empty lists."""
    result, _, _, _ = _campaign()

    assert result.all_probes
    assert result.all_findings, "fake target never breached; determinism tests would be vacuous"


def test_findings_name_the_strategy_that_breached_when_goals_run_concurrently():
    """record() runs after the wave, so the breaching strategy must travel back with the probes."""
    result, _, sink, _ = _campaign(goal_concurrency=3)

    findings = [data for event, data in sink.payloads if event == "finding"]
    assert len(findings) == len(result.all_findings) > 0
    for finding in findings:
        assert finding["strategy"] and finding["phase"] in {"agentic", "breadth", "depth"}


def test_the_report_does_not_depend_on_scheduling():
    """Same inputs must give the same probes and findings whatever finishes first."""
    runs = []
    for _ in range(3):
        result, _, _, _ = _campaign()
        runs.append(
            (
                [(probe.category, probe.technique) for probe in result.all_probes],
                [finding.goal.id for finding in result.all_findings],
                result.grade(),
            )
        )

    assert runs[0] == runs[1] == runs[2]


def test_serial_and_windowed_agree_on_the_campaign():
    """goal_concurrency=1 is the escape hatch; it must not change what is found."""
    serial, _, _, serial_elapsed = _campaign(goal_concurrency=1)
    windowed, _, _, windowed_elapsed = _campaign(goal_concurrency=3)

    assert serial.all_findings, "serial run found nothing; the comparison would be vacuous"
    assert [f.goal.id for f in serial.all_findings] == [
        f.goal.id for f in windowed.all_findings
    ]
    assert serial.grade() == windowed.grade()
    assert windowed_elapsed < serial_elapsed


def test_a_window_of_one_is_fully_sequential():
    _, target, _, _ = _campaign(goal_concurrency=1, recon_concurrency=1)

    assert target.peak_concurrent == 1
