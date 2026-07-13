"""Built-in assembly and direct registration of engine extensions."""
from __future__ import annotations

from collections.abc import Iterable

from .prompts import PromptAttack, BUILTIN_PROMPTS, register_prompt
from .carriers import Carrier, BUILTIN_CARRIERS, register_carrier
from .strategies import Strategy, register_strategy
from .strategies.breadth import Breadth
from .strategies.bypass import Bypass
from .strategies.crescendo import Crescendo
from .strategies.exfiltration import Exfiltration
from .strategies.framing import Framing
from .strategies.indirect_injection import IndirectInjection
from .strategies.refund_abuse import RefundAbuse
from .strategies.ssrf import Ssrf

BUILTIN_STRATEGIES: tuple[Strategy, ...] = (
    Ssrf(),
    IndirectInjection(),
    Exfiltration(),
    RefundAbuse(),
    Breadth(),
    Bypass(),
    Framing(),
    Crescendo(),
)


def register_extensions(*, prompts: Iterable[PromptAttack] = (), carriers: Iterable[Carrier] = (),
                        strategies: Iterable[Strategy] = ()) -> None:
    """Register extension instances directly; individual names remain replacement-idempotent."""
    for prompt in prompts:
        register_prompt(prompt)
    for carrier in carriers:
        register_carrier(carrier)
    for strategy in strategies:
        register_strategy(strategy)


def register_builtin_strategies() -> None:
    register_extensions(strategies=BUILTIN_STRATEGIES)


def register_builtin_extensions() -> None:
    register_extensions(
        prompts=BUILTIN_PROMPTS,
        carriers=BUILTIN_CARRIERS,
        strategies=BUILTIN_STRATEGIES,
    )
