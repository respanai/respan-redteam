"""The target contract — the whole integration surface of the engine.

The engine drives every target as `chat = target.open(); reply = chat.send(user_message)`. This is
the honest shape of a real chatbot/agent: you can only *send a user message* and read the reply, you
can never set an assistant turn. A target is an adapter you implement over your own agent (this
Protocol) — run the engine in-process via `run_campaign(target)`, or keep the target on your own
machine and let a remote engine drive it over the WebSocket bridge (CLI `--adapter`).

A stateless backend (an OpenAI-style endpoint that wants the full message array each call) keeps its
own history inside its `Chat`; a server-owned session just posts the user turn to its conversation id.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Chat(Protocol):
    """One live conversation with a target. `send` is the only way to advance it."""
    def send(self, user_message: str) -> str: ...
    def transcript(self) -> list[dict]: ...        # the conversation so far: [{role, content}, ...]


@runtime_checkable
class Target(Protocol):
    label: str
    def open(self) -> Chat: ...                     # a fresh, isolated conversation (one per attack)
