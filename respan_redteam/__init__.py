"""Adaptive red-team engine for AI agents.

Implement the `Target` and `Chat` protocols, then call `run_campaign(target)`. Prompt attacks,
carriers, and strategies can be extended through their public registration functions.
"""
from .campaign import run_campaign
from .config import (
    BudgetConfig,
    DEFAULT_BUDGET,
    DEFAULT_ENGINE_CONFIG,
    EngineConfig,
    LLMConfig,
)
from .models import CampaignResult, Finding, Probe, Outcome, Severity, TargetType, ReconProfile
from .goals import Goal
from .target import Chat, Target
from .events import Event
from .prompts import PromptAttack, BREADTH, DEPTH, compose, register_prompt, registered_prompts
from .carriers import (Carrier, COMPREHENSION, ENCODING, FunctionalCarrier, register_carrier,
                       registered_carriers)
from .execution import run_single_turn
from .strategies import (Strategy, StrategyInput, StrategyStage, applicable_strategies,
                         register_strategy, registered_strategies)
from .extensions import (BUILTIN_STRATEGIES, register_builtin_extensions,
                         register_builtin_strategies, register_extensions)

register_builtin_extensions()

__all__ = [
    # run a campaign
    "run_campaign",
    "EngineConfig", "LLMConfig", "BudgetConfig", "DEFAULT_ENGINE_CONFIG", "DEFAULT_BUDGET",
    # target contract (implement an adapter over your own agent)
    "Target", "Chat",
    # results + events
    "CampaignResult", "Finding", "Probe", "Outcome", "Severity", "TargetType", "ReconProfile", "Event",
    # extension API — register your own attack vectors, bypasses, and strategies
    "Goal", "PromptAttack", "Carrier", "FunctionalCarrier", "Strategy", "StrategyInput", "StrategyStage",
    "BREADTH", "DEPTH", "COMPREHENSION", "ENCODING", "compose",
    "run_single_turn",
    "register_prompt", "registered_prompts",
    "register_carrier", "registered_carriers",
    "register_strategy", "registered_strategies", "applicable_strategies",
    "BUILTIN_STRATEGIES", "register_builtin_strategies",
    "register_extensions",
]
