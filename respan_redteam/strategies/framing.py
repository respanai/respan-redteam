"""Depth-only attack framing strategy."""
from ..prompts.core import depth_prompts
from ..runtime import budget_can_send, current_profile
from ..execution.single_turn import run_single_turn
from ..models import Probe
from .core import Strategy


class Framing(Strategy):
    name, priority, min_budget = "framing", 35, 2

    def run(self, goal, context):
        probes: list[Probe] = []
        profile = current_profile()
        for attack in depth_prompts():
            if not budget_can_send():
                break
            probe = run_single_turn(goal, attack.build(goal.text, profile),
                                    f"framing:{attack.name}")
            if probe is None:
                break
            probes.append(probe)
            if probe.breached:
                break
        return probes
