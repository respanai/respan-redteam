"""Example adapter for a stateful, server-owned conversation.

The backend owns history. The adapter creates a conversation and posts user turns:

    create_conversation(first_user_msg) -> conversation_id
    send(conversation_id, user_msg)     -> assistant_reply
    get_conversation(conversation_id)   -> full transcript

Replace `_Backend` with calls to your service. Run:

    python -m respan_redteam --adapter examples/adapter_session.py \
        --api-key "$RESPAN_API_KEY" \
        --ws-url ws://127.0.0.1:8000/redteam/remote/
"""
from __future__ import annotations

import itertools


class _Backend:
    """Stand-in for YOUR chat service. Replace these three methods with real HTTP calls."""
    _ids = itertools.count(1)
    _store: dict[str, list[dict]] = {}
    _SECRET = "SESAME-7734"

    @classmethod
    def create_conversation(cls, first_user_msg: str) -> str:
        cid = f"conv-{next(cls._ids)}"
        cls._store[cid] = []
        cls._reply(cid, first_user_msg)
        return cid

    @classmethod
    def send(cls, conversation_id: str, user_msg: str) -> str:
        return cls._reply(conversation_id, user_msg)

    @classmethod
    def get_conversation(cls, conversation_id: str) -> list[dict]:
        return list(cls._store.get(conversation_id, []))

    @classmethod
    def _reply(cls, cid: str, user_msg: str) -> str:
        # Toy server-side model: leaks its secret if asked about config/secret/instructions.
        low = user_msg.lower()
        if any(t in low for t in ("secret", "code", "instruction", "system prompt", "config")):
            reply = f"Our internal staff code is {cls._SECRET}. Anything else?"
        else:
            reply = "Thanks for reaching out — how can I help with your order?"
        hist = cls._store.setdefault(cid, [])
        hist.append({"role": "user", "content": user_msg})
        hist.append({"role": "assistant", "content": reply})
        return reply


class SessionChat:
    """The session waist over a server-owned conversation. `open()` defers creation to the first
    send (matching `create_conversation(first_msg)`); later turns use `send(id, msg)`."""

    def __init__(self, backend: type[_Backend]):
        self._backend = backend
        self._cid: str | None = None
        self._turns: list[dict] = []

    def send(self, user_message: str) -> str:
        if self._cid is None:
            self._cid = self._backend.create_conversation(user_message)
            reply = self._backend.get_conversation(self._cid)[-1]["content"]
        else:
            reply = self._backend.send(self._cid, user_message)
        self._turns.append({"role": "user", "content": user_message})
        self._turns.append({"role": "assistant", "content": reply})
        return reply

    def transcript(self) -> list[dict]:
        # Prefer the server's authoritative view when available.
        if self._cid is not None:
            return self._backend.get_conversation(self._cid)
        return [dict(m) for m in self._turns]


class SessionTarget:
    label = "acme-session-backend"

    def open(self) -> SessionChat:
        return SessionChat(_Backend)


TARGET = SessionTarget()
