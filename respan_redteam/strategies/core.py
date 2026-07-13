"""Strategy contract, stages, applicability helpers, and registration."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

from ..judge import DISCLOSURE_CATEGORIES, INJECTION_CATEGORIES
from ..goals import Goal
from ..models import Probe, ReconProfile


class StrategyStage(str, Enum):
    AGENTIC = "agentic"
    BREADTH = "breadth"
    DEPTH = "depth"


@dataclass(frozen=True)
class StrategyInput:
    seeds: tuple[str, ...] = ()


class Strategy(ABC):
    name: str = ""
    stage: StrategyStage = StrategyStage.DEPTH
    priority: int = 100
    min_budget: int = 2

    def applies(self, goal: Goal, profile: ReconProfile) -> bool:
        return True

    @abstractmethod
    def run(self, goal: Goal, context: StrategyInput) -> list[Probe]:
        """Spend target probes against one goal and return every resulting probe."""


def is_disclosure(goal: Goal, profile: ReconProfile) -> bool:
    return goal.category in DISCLOSURE_CATEGORIES


def is_filter_evadable(goal: Goal, profile: ReconProfile) -> bool:
    return goal.category in DISCLOSURE_CATEGORIES or goal.category in INJECTION_CATEGORIES


def is_multiturn(goal: Goal, profile: ReconProfile) -> bool:
    return goal.multi_turn


_REGISTERED: list[Strategy] = []


def register_strategy(strategy: Strategy) -> Strategy:
    global _REGISTERED
    _REGISTERED = [item for item in _REGISTERED if item.name != strategy.name]
    _REGISTERED.append(strategy)
    return strategy


def registered_strategies() -> list[Strategy]:
    return list(_REGISTERED)


def applicable_strategies(stage: StrategyStage, goal: Goal,
                          profile: ReconProfile) -> list[Strategy]:
    return sorted(
        (strategy for strategy in _REGISTERED
         if strategy.stage is stage and strategy.applies(goal, profile)),
        key=lambda strategy: strategy.priority,
    )


def depth_strategies(goal: Goal, profile: ReconProfile) -> list[Strategy]:
    return applicable_strategies(StrategyStage.DEPTH, goal, profile)
