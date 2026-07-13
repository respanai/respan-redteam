"""Carrier bypass strategy."""
from __future__ import annotations

from ..carriers.core import registered_carriers
from ..runtime import budget_can_send
from ..execution.single_turn import run_single_turn
from ..goals import Goal
from ..models import Probe
from .core import Strategy, is_filter_evadable

def _send_judge(goal: Goal, text: str, technique: str, probes: list[Probe]) -> bool:
    p = run_single_turn(goal, text, technique)
    if p is None:
        return False
    probes.append(p)
    return p.breached


class Bypass(Strategy):
    """The evasion matrix: smuggle the best breadth frame, then the raw goal, through the carrier
    ladder. Carrier metadata owns eligibility and ordering, so plugins require no engine changes."""
    name, priority, min_budget = "bypass", 10, 2

    def applies(self, goal, profile):
        return is_filter_evadable(goal, profile)

    def run(self, goal, context):
        probes: list[Probe] = []
        carriers = sorted(
            (c for c in registered_carriers() if c.bypass_enabled),
            key=lambda c: c.bypass_priority,
        )
        # 1) best breadth frame x carriers explicitly marked safe for legible composition.
        seed = next((s for s in context.seeds if s and s.strip()), None)
        if seed:
            for c in (c for c in carriers if c.frame_compatible):
                if not budget_can_send():
                    return probes
                if _send_judge(goal, c.apply(seed), f"bypass:frame+{c.name}", probes):
                    return probes
        # 2) raw goal x every enabled carrier, once, in declared priority order.
        for c in carriers:
            if not budget_can_send():
                return probes
            if _send_judge(goal, c.apply(goal.text), f"bypass:{c.name}", probes):
                return probes
        return probes
