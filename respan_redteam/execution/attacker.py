"""Shared attacker-LLM helpers for the multi-turn strategies (crescendo, deceptive-delight, bad-likert)."""
from __future__ import annotations

from .. import model_client
from ..runtime import current_config


def history_str(conv: list[dict], cap: int = 400) -> str:
    """Compact last-6-turn transcript for the attacker planner prompt."""
    if not conv:
        return "(none yet)"
    return "\n".join(f"{m['role'].upper()}: {m['content'][:cap]}" for m in conv[-6:])


def attacker_msg(system: str, user: str, max_tokens: int = 500) -> str:
    """One attacker-LLM turn -> the next user message to send (plain text)."""
    res = model_client.complete(current_config().llm.model_attacker, user, system=system,
                       max_tokens=max_tokens, temperature=1.0)
    return res.text.strip().strip('"')
