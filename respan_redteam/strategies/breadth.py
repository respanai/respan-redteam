"""Registered breadth strategy over the prompt-attack catalogue."""
from __future__ import annotations

from ..models import Probe
from ..runtime import current_profile
from ..prompts.framings import BUILTIN_ATTACK_NAMES
from ..prompts.core import breadth_prompts
from ..execution.single_turn import run_single_turn
from .core import Strategy, StrategyInput, StrategyStage


class Breadth(Strategy):
    name = "breadth"
    stage = StrategyStage.BREADTH
    priority = 10
    min_budget = 1
    max_frames = 4

    def run(self, goal, context: StrategyInput):
        probes: list[Probe] = []
        attacks = breadth_prompts()
        # Cap the built-in framings to the strongest few (budget), but always fire user-registered
        # breadth attacks — registering one is an explicit opt-in to run it.
        builtin = [a for a in attacks if a.name in BUILTIN_ATTACK_NAMES][:self.max_frames]
        custom = [a for a in attacks if a.name not in BUILTIN_ATTACK_NAMES]
        attacks = builtin + custom
        for attack in attacks:
            probe = run_single_turn(
                goal, attack.build(goal.text, current_profile()), f"seed:{attack.name}",
            )
            if probe is None:
                break
            probes.append(probe)
            if probe.breached:
                break
        return probes
