"""PromptAttack contract, composition, and registration."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..carriers.core import Carrier
from ..models import ReconProfile

BREADTH = "breadth"
DEPTH = "depth"


class PromptAttack(ABC):
    name: str = ""
    tier: str = BREADTH

    @abstractmethod
    def build(self, goal_text: str, profile: ReconProfile) -> str:
        """Return one user message framing the goal for the target."""


class _ComposedAttack(PromptAttack):
    def __init__(self, attack: PromptAttack, carrier: Carrier):
        self.name = f"{attack.name}+{carrier.name}"
        self.tier = attack.tier
        self._attack = attack
        self._carrier = carrier

    def build(self, goal_text: str, profile: ReconProfile) -> str:
        return self._carrier.apply(self._attack.build(goal_text, profile))


def compose(attack: PromptAttack, carrier: Carrier) -> PromptAttack:
    return _ComposedAttack(attack, carrier)


_REGISTERED: list[PromptAttack] = []


def register_prompt(attack: PromptAttack) -> PromptAttack:
    global _REGISTERED
    _REGISTERED = [item for item in _REGISTERED if item.name != attack.name]
    _REGISTERED.append(attack)
    return attack


def registered_prompts() -> list[PromptAttack]:
    return list(_REGISTERED)


def breadth_prompts() -> list[PromptAttack]:
    return [attack for attack in _REGISTERED if attack.tier == BREADTH]


def depth_prompts() -> list[PromptAttack]:
    return [attack for attack in _REGISTERED if attack.tier == DEPTH]


all_prompts = registered_prompts
