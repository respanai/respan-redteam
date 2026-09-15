"""Guards for the concurrent recon battery.

Recon is the one phase where every probe is independent — nine fixed prompts,
each in its own conversation, whose replies are only concatenated into one blob
for synthesis. It also runs first, on every campaign, before any strategy is
chosen, so serialising it put nine round-trips in front of every scan.

Sending them concurrently has to preserve three things:

  - the probe budget is a plain counter, and overshooting it means sending a
    customer's agent more traffic than the campaign was authorised to
  - the returned probes drive the synthesis blob and the report, so their order
    must not depend on which reply landed first
  - a target that errors or rate-limits still yields a usable partial battery
"""

import threading
import time

import pytest

from respan_redteam.config import BudgetConfig, EngineConfig
from respan_redteam.models import TargetErrorResponse
from respan_redteam.recon import RECON_PROBES, run_recon
from respan_redteam.runtime import campaign_scope, current_budget

LATENCY_SECONDS = 0.05


class _FakeChat:
    def __init__(self, target):
        self._target = target

    def send(self, message):
        # Count the overlap around the SLEEP: that is the part that actually
        # runs concurrently. Counting after it would leave a microsecond-wide
        # window and report peak_concurrent == 1 even when fully parallel.
        with self._target.lock:
            self._target.sends += 1
            self._target.concurrent += 1
            self._target.peak_concurrent = max(
                self._target.peak_concurrent, self._target.concurrent
            )
        try:
            time.sleep(LATENCY_SECONDS)
            if message in self._target.fail_prompts:
                raise RuntimeError("target refused the connection")
            return f"reply to {message[:24]}"
        finally:
            with self._target.lock:
                self._target.concurrent -= 1

    def transcript(self):
        return []


class _FakeTarget:
    label = "fake"

    def __init__(self, fail_prompts=()):
        self.sends = 0
        self.concurrent = 0
        self.peak_concurrent = 0
        self.lock = threading.Lock()
        self.fail_prompts = set(fail_prompts)

    def open(self):
        return _FakeChat(self)


@pytest.fixture(autouse=True)
def _stub_synthesis(monkeypatch):
    """Recon synthesis is one LLM call after the battery; not what these test."""
    from respan_redteam import recon as recon_module

    monkeypatch.setattr(
        recon_module.model_client,
        "complete_json",
        lambda *args, **kwargs: {"target_type": "llm", "guardrail_strength": "low"},
    )


def _run(*, max_probes=56, recon_probes=9, concurrency=9, fail_prompts=()):
    target = _FakeTarget(fail_prompts=fail_prompts)
    config = EngineConfig(
        budget=BudgetConfig(
            max_target_probes=max_probes,
            recon_probes=recon_probes,
            recon_concurrency=concurrency,
        )
    )
    with campaign_scope(config, target, None):
        started = time.perf_counter()
        profile, probes = run_recon(recon_probes=recon_probes)
        elapsed = time.perf_counter() - started
        return profile, probes, target, current_budget().sent, elapsed


def test_the_battery_runs_concurrently():
    _, probes, target, _, elapsed = _run()

    assert len(probes) == 9
    assert target.peak_concurrent > 1, "battery was sent serially"
    assert elapsed < LATENCY_SECONDS * 9 * 0.6, "no wall-clock gain over serial"


def test_probes_are_returned_in_battery_order():
    """Synthesis and the report read these, so order must not follow completion."""
    _, probes, _, _, _ = _run()

    assert [probe.technique for probe in probes] == [name for name, _, _ in RECON_PROBES]


@pytest.mark.parametrize("max_probes", [0, 1, 4, 8, 9, 56])
def test_the_probe_budget_is_never_overshot(max_probes):
    _, probes, target, budget_sent, _ = _run(max_probes=max_probes)

    assert target.sends <= max_probes
    assert budget_sent <= max_probes
    assert len(probes) <= max_probes


def test_a_failing_probe_still_yields_the_rest_of_the_battery():
    failing = RECON_PROBES[2][2]
    _, probes, _, _, _ = _run(fail_prompts=[failing])

    assert len(probes) == 9
    errored = [probe for probe in probes if isinstance(probe.response, TargetErrorResponse)]
    assert len(errored) == 1
    assert errored[0].technique == RECON_PROBES[2][0]


def test_concurrency_is_capped_by_configuration():
    """A rate-limited target can dial the fan-out down."""
    _, probes, target, _, _ = _run(concurrency=3)

    assert len(probes) == 9
    assert target.peak_concurrent <= 3


def test_concurrency_of_one_is_fully_serial():
    """The escape hatch restores the previous behaviour exactly."""
    _, probes, target, _, _ = _run(concurrency=1)

    assert len(probes) == 9
    assert target.peak_concurrent == 1
    assert [probe.technique for probe in probes] == [name for name, _, _ in RECON_PROBES]


def test_serial_and_parallel_agree_on_the_battery():
    """Same probes, same order, same content — only the wall clock differs."""
    _, serial_probes, _, _, serial_elapsed = _run(concurrency=1)
    _, parallel_probes, _, _, parallel_elapsed = _run(concurrency=9)

    assert [probe.technique for probe in serial_probes] == [
        probe.technique for probe in parallel_probes
    ]
    assert [probe.response for probe in serial_probes] == [
        probe.response for probe in parallel_probes
    ]
    assert parallel_elapsed < serial_elapsed / 2
