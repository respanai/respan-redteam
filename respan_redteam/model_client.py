"""Thin OpenAI Chat Completions wrapper (retry-with-backoff, strict-JSON helper)."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from . import config
from .runtime import Usage, record_usage   # token usage is recorded into the ambient campaign

_CLIENT: OpenAI | None = None


def _client() -> OpenAI:
    global _CLIENT
    if _CLIENT is None:
        kwargs: dict[str, Any] = {"timeout": 120, "max_retries": 0}
        if config.OPENAI_API_KEY:
            kwargs["api_key"] = config.OPENAI_API_KEY
        if config.OPENAI_BASE_URL:
            kwargs["base_url"] = config.OPENAI_BASE_URL
        _CLIENT = OpenAI(**kwargs)
    return _CLIENT


@dataclass
class LLMResult:
    text: str
    usage: Usage


class TransientLLMError(RuntimeError):
    pass


def complete(
    model_id: str,
    user: str,
    system: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 1.0,
    max_retries: int = 4,
) -> LLMResult:
    """One chat-completion call. Token usage is recorded into the ambient campaign (no-op outside
    a campaign scope)."""
    chat = [{"role": "user", "content": user}]
    if system:
        chat = [{"role": "system", "content": system}, *chat]

    delay = 1.5
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = _client().chat.completions.create(
                model=model_id,
                messages=chat,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            choice = resp.choices[0]
            text = choice.message.content or ""
            u = resp.usage
            usage = Usage(
                input_tokens=getattr(u, "prompt_tokens", 0) or 0,
                output_tokens=getattr(u, "completion_tokens", 0) or 0,
            )
            record_usage(usage)
            return LLMResult(text=text, usage=usage)
        except Exception as exc:  # noqa: BLE001 -- classify below
            last_exc = exc
            name = type(exc).__name__
            msg = str(exc)
            transient = (
                "RateLimit" in name or "429" in msg or "Timeout" in name
                or "APIConnection" in name or "InternalServer" in name
                or "500" in msg or "503" in msg or "overloaded" in msg.lower()
            )
            if not transient or attempt == max_retries - 1:
                break
            time.sleep(delay)
            delay *= 2
    raise TransientLLMError(f"completion failed for {model_id}: {last_exc}")


_JSON_RE = re.compile(r"\{.*\}|\[.*\]", re.DOTALL)


def complete_json(
    model_id: str,
    user: str,
    system: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.4,
    max_retries: int = 4,
) -> Any:
    """Complete and parse the first JSON object/array; appends a strict-JSON instruction
    and strips ```json fences. Raises ValueError if none parses after retries."""
    sys = (system or "") + "\n\nRespond with ONLY valid JSON. No prose, no markdown fences."
    last_text = ""
    for attempt in range(max_retries):
        res = complete(model_id, user, system=sys.strip(), max_tokens=max_tokens,
                       temperature=temperature if attempt == 0 else min(1.0, temperature + 0.2),
                       max_retries=2)
        last_text = res.text
        parsed = _try_parse_json(res.text)
        if parsed is not None:
            return parsed
    raise ValueError(f"no JSON parsed from {model_id} after {max_retries} tries; last: {last_text[:200]!r}")


def _try_parse_json(text: str) -> Any | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except Exception:
        pass
    m = _JSON_RE.search(text)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None
