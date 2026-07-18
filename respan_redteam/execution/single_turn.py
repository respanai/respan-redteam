"""Shared execution primitives for strategy implementations.

Single-turn strategies used to duplicate the same open/send/judge/Probe construction sequence.
Keeping it here makes the budget leaf, event order, and evidence semantics consistent for built-in
and plugin strategies.
"""
from __future__ import annotations

from collections.abc import Callable

from ..runtime import BudgetExhausted, open_chat
from ..goals import Goal
from ..models import Probe, Round, TargetErrorResponse


def run_single_turn(
    goal: Goal,
    message: str,
    technique: str,
    *,
    chat=None,
    response_for_judge: Callable[[str], str] | None = None,
) -> Probe | None:
    """Send and judge one attack message.

    ``response_for_judge`` supports transformations such as translating a foreign-language reply
    for the judge while retaining the raw target response as report evidence. ``None`` means the
    target budget was exhausted before the send.
    """
    chat = chat or open_chat()
    try:
        response = chat.send(message, technique=technique)
    except BudgetExhausted:
        return None

    graded_response = response if isinstance(response, TargetErrorResponse) else (
        response_for_judge(response) if response_for_judge else response
    )
    round_ = Round.judged(goal, message, graded_response)
    round_.response = response
    return Probe(category=goal.category, technique=technique, rounds=[round_])
