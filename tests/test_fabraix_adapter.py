from __future__ import annotations

import io
import json
import os
import sys
from importlib.util import module_from_spec, spec_from_file_location
from unittest.mock import patch


def _adapter():
    path = os.path.join(os.path.dirname(__file__), "..", "examples", "adapter_fabraix.py")
    spec = spec_from_file_location("adapter_fabraix_test", path)
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def test_fabraix_chat_consumes_complete_event_and_records_transcript():
    adapter = _adapter()
    start = _Response(b'{"sessionId":"playsess_test"}')
    body = b'{"event":"thinking","data":{}}\n' + json.dumps({
        "event": "complete", "data": {"content": "hello", "success": True, "tool_calls": [
            {"name": "about_fabraix", "result": "public result", "blocked": False}
        ]}
    }).encode() + b"\n"
    with patch.object(adapter, "urlopen", side_effect=[start, _Response(body)]) as open_url:
        chat = adapter.FabraixTarget("https://example.test/stream", variant_id="playvar_test").open()
        assert "hello" in chat.send("hi")
        assert "public result" in chat.transcript()[-1]["content"]
        assert "blocked=False" in chat.transcript()[-1]["content"]
        assert "fabraix_success:true" in chat.transcript()[-1]["content"]

    start_request, chat_request = open_url.call_args_list[0].args[0], open_url.call_args_list[1].args[0]
    assert start_request.full_url.endswith("?variant_id=playvar_test")
    assert json.loads(start_request.data)["challenge_id"] == "access-code-001"
    assert json.loads(chat_request.data) == {"session_id": chat._session_id, "message": "hi"}
    assert chat.transcript() == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello\n\n[tool_call:about_fabraix blocked=False]\npublic result\n\n[fabraix_success:true]"},
    ]


def test_open_creates_isolated_sessions():
    adapter = _adapter()
    first, second = adapter.FabraixTarget().open(), adapter.FabraixTarget().open()
    assert first is not second
    assert first._challenge_id == second._challenge_id == "access-code-001"
