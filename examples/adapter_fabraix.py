"""Adapter for the public Fabraix Playground chat.

Run a scan with::

    respan-redteam scan examples/adapter_fabraix.py

The playground keeps conversation state on the server.  A new random session is
created for every ``Target.open()``, so each attack starts with an isolated
conversation.  The stream is newline-delimited JSON; ``thinking`` events are
progress updates and the ``complete`` event contains the assistant response.
"""
from __future__ import annotations

import json
import os
import uuid
from http.client import HTTPResponse
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


_DEFAULT_URL = "https://api.fabraix.com/v1/playground/chat/stream"


class FabraixChat:
    def __init__(self, endpoint: str = _DEFAULT_URL, challenge_id: str = "access-code-001",
                 variant_id: str | None = None):
        self._endpoint = endpoint
        self._challenge_id = challenge_id
        self._variant_id = variant_id
        self._session_id: str | None = None
        self._turns: list[dict[str, str]] = []

    def send(self, user_message: str) -> str:
        if self._session_id is None:
            self._session_id = self._start_session()
        request = Request(
            self._endpoint,
            data=json.dumps({"session_id": self._session_id, "message": user_message}).encode(),
            headers={
                "Accept": "*/*",
                "Content-Type": "application/json",
                "Origin": "https://playground.fabraix.com",
                "User-Agent": "respan-redteam-fabraix-adapter/1.0",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=float(os.getenv("FABRAIX_TIMEOUT", "120"))) as response:
                reply = self._read_completion(response)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"Fabraix request failed ({exc.code}): {detail}") from exc

        self._turns.extend([
            {"role": "user", "content": user_message},
            {"role": "assistant", "content": reply},
        ])
        return reply

    def _start_session(self) -> str:
        start_url = self._endpoint.rsplit("/playground/chat/stream", 1)[0] + "/playground/sessions/start"
        if self._variant_id:
            start_url += "?" + urlencode({"variant_id": self._variant_id})
        request = Request(
            start_url,
            data=json.dumps({
                "challenge_id": self._challenge_id,
                "user_identifier": f"respan-{uuid.uuid4().hex}",
            }).encode(),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Origin": "https://playground.fabraix.com",
                "User-Agent": "respan-redteam-fabraix-adapter/1.0",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=float(os.getenv("FABRAIX_TIMEOUT", "120"))) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"Fabraix session start failed ({exc.code}): {detail}") from exc
        session_id = payload.get("sessionId") or payload.get("session_id")
        if not session_id:
            raise RuntimeError("Fabraix session start returned no session ID")
        return str(session_id)

    @staticmethod
    def _read_completion(response: HTTPResponse) -> str:
        """Consume NDJSON and preserve both final text and structured tool results.

        Fabraix can return a refusal in ``content`` while a tool invocation and its
        result appear separately in ``data.tool_calls``. A red-team adapter must not
        discard that second channel because it is where an action-side breach lives.
        """
        for raw_line in response:
            line = raw_line.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "complete":
                data = event.get("data") or {}
                content = str(data.get("content") or "")
                tool_calls = data.get("tool_calls") or []
                traces = []
                for call in tool_calls:
                    if not isinstance(call, dict):
                        continue
                    name = call.get("name") or call.get("tool_name") or "unknown_tool"
                    result = call.get("result")
                    if result is not None:
                        if not isinstance(result, str):
                            result = json.dumps(result, ensure_ascii=False)
                        traces.append(
                            f"[tool_call:{name} blocked={call.get('blocked')}]\n{result}"
                        )
                if data.get("success") is True:
                    traces.append("[fabraix_success:true]")
                return "\n\n".join(part for part in (content, *traces) if part)
        raise RuntimeError("Fabraix stream ended without a complete event")

    def transcript(self) -> list[dict[str, str]]:
        return list(self._turns)


class FabraixTarget:
    label = "fabraix-playground"

    def __init__(self, endpoint: str = _DEFAULT_URL, challenge_id: str = "access-code-001",
                 variant_id: str | None = None):
        self._endpoint = endpoint
        self._challenge_id = challenge_id
        self._variant_id = variant_id

    def open(self) -> FabraixChat:
        return FabraixChat(self._endpoint, self._challenge_id, self._variant_id)


TARGET = FabraixTarget(
    os.getenv("FABRAIX_CHAT_URL", _DEFAULT_URL),
    os.getenv("FABRAIX_CHALLENGE_ID", "access-code-001"),
    os.getenv("FABRAIX_VARIANT_ID"),
)
