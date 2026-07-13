"""Offline tests for the CLI progress renderer, adapter loader, and failure classification.

Run directly:  .venv/bin/python tests/test_cli.py   (also importable under pytest)."""
from __future__ import annotations

import asyncio
import io
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import AsyncMock, patch

from rich.console import Console

from respan_redteam.cli import (_Progress, _auth_main, _campaign_url, _connect, _error, _explain,
                                _load_adapter, _open_adapter, _required,
                                _retryable_connection_error, _validate_api_key, _write_report)
from respan_redteam.credentials import (
    CredentialStoreUnavailable,
    credential_name,
    resolve_api_key,
    save_api_key,
)


def _progress(buf, *, terminal: bool, quiet: bool = False) -> _Progress:
    """A _Progress whose rich Console writes to `buf`; `terminal` picks the colour + live-counter
    path (a StringIO is never a real TTY, so we force it)."""
    if terminal:
        console = Console(
            file=buf,
            force_terminal=True,
            no_color=False,
            color_system="standard",
            width=100,
        )
    else:
        console = Console(file=buf, force_terminal=False, width=100)
    return _Progress(console=console, quiet=quiet)


_EVENTS = [
    ("session.start", {"target": "acme"}),
    ("recon.profile.ready", {"target_type": "agent", "guardrail_strength": "high",
                             "extraction_confidence": 0.5, "detected_tools": [{"name": "fetch_url"}]}),
    ("category.start", {"phase": "breadth", "category": "LLM07", "goal": "leak"}),
    # attack.attempt carries the technique; the following verdict no longer repeats it.
    ("attack.attempt", {"technique": "seed:direct", "prompt": "hi"}),
    ("target.response", {"probes_used": 5}),
    ("judge.verdict", {"outcome": "refused"}),
    ("attack.attempt", {"technique": "seed:roleplay", "prompt": "hi"}),
    ("judge.verdict", {"outcome": "success"}),
    ("finding.critical", {"title": "Secret", "severity": "critical"}),
    ("report.ready", {"grade": "F", "score": 40, "findings": 1, "probes": 12}),
]

DEFAULT_URL = "wss://redteam.respan.ai/redteam/remote/"


def test_nontty_logs_every_verdict_and_no_escapes():
    buf = io.StringIO()
    p = _progress(buf, terminal=False)        # not a terminal -> plain text, no live counter
    for e, d in _EVENTS:
        p.sink(e, d)
    p.close()
    out = buf.getvalue()
    assert "\x1b[" not in out                 # rich emits no ANSI when not a terminal
    assert "seed:direct  refused" in out      # refusals ARE logged when piped
    assert "BREACH" in out and "★ FINDING" in out
    assert "✔ complete · grade F" in out


def test_tty_keeps_counters_and_suppresses_refusals():
    buf = io.StringIO()
    p = _progress(buf, terminal=True)         # a terminal -> colour + a live in-place counter
    for e, d in _EVENTS:
        p.sink(e, d)
    out = buf.getvalue()
    p.close()
    assert p.probes == 5 and p.breaches == 1 and p.findings == 1 and p.refused == 1
    assert "\x1b[" in out                       # ANSI on a terminal
    assert "BREACH" in out                      # a breach scrolls its own line...
    assert "seed:direct  refused" not in out    # ...a refusal only rides the live counter


def test_quiet_emits_nothing():
    buf = io.StringIO()
    p = _progress(buf, terminal=True, quiet=True)
    for e, d in _EVENTS:
        p.sink(e, d)
    p.close()
    assert buf.getvalue() == ""


def _write_adapter(body: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(body)
    return path


# A native adapter: a Target with .open() -> Chat, no engine helpers.
_NATIVE_TARGET = (
    "class _C:\n"
    "    def send(self, m): return 'ok'\n"
    "    def transcript(self): return []\n"
    "class _T:\n"
    "    label = 'obj'\n"
    "    def open(self): return _C()\n"
)


def test_load_adapter_resolves_target_object():
    path = _write_adapter(_NATIVE_TARGET + "TARGET = _T()\n")
    tgt = _load_adapter(path)
    assert callable(getattr(tgt, "open", None)) and tgt.open().send("hi") == "ok"
    os.unlink(path)


def test_load_adapter_rejects_target_without_open():
    path = _write_adapter("def send(conv):\n    return 'bare'\n")   # bare callable is no longer valid
    try:
        _load_adapter(path)
        assert False, "expected ValueError for an adapter without .open()"
    except ValueError:
        pass
    os.unlink(path)


def test_load_adapter_build_factory_and_bad_symbol():
    path = _write_adapter(_NATIVE_TARGET + "def build_target():\n    return _T()\n")
    assert _load_adapter(path).open().send("x") == "ok"
    try:
        _load_adapter(path, symbol="NOPE")
        assert False, "expected ValueError for missing symbol"
    except ValueError:
        pass
    os.unlink(path)


def test_explain_classifies_failures_without_traceback():
    import websockets.exceptions as we
    assert "refused" in _explain(ConnectionRefusedError())
    assert "malformed" in _explain(we.InvalidURI("bad", "no"))
    assert "timed out" in _explain(asyncio.TimeoutError())


def test_retry_classification_skips_permanent_url_errors():
    import websockets.exceptions as we
    assert _retryable_connection_error(ConnectionRefusedError())
    assert _retryable_connection_error(asyncio.TimeoutError())
    assert not _retryable_connection_error(we.InvalidURI("bad", "no"))


def test_write_report_creates_parent_and_writes_clean_json():
    with tempfile.TemporaryDirectory() as root:
        path = os.path.join(root, "reports", "result.json")
        _write_report({"grade": "A", "findings": []}, "json", path)
        with open(path, encoding="utf-8") as report:
            assert report.read() == '{\n  "grade": "A",\n  "findings": []\n}\n'


def test_error_output_has_hint_without_traceback_by_default():
    output = io.StringIO()
    with redirect_stderr(output):
        _error("could not connect", ConnectionRefusedError(), hint="check the URL")
    text = output.getvalue()
    assert text.startswith("error: could not connect: connection refused")
    assert "hint: check the URL" in text and "Traceback" not in text


def test_required_rejects_malformed_remote_operations():
    try:
        _required({"op": "send", "id": "1"}, "id", "chat_id", "message")
        assert False, "expected malformed operation to fail"
    except RuntimeError as exc:
        assert "chat_id" in str(exc) and "message" in str(exc)


def test_campaign_url_discards_websocket_route():
    assert _campaign_url(
        "wss://redteam.respan.ai/redteam/remote/", "campaign-1"
    ) == "https://redteam.respan.ai/campaign/campaign-1"
    assert _campaign_url(
        "ws://localhost:8000/redteam/remote/?token=x", "campaign-2"
    ) == "http://localhost:8000/campaign/campaign-2"


def test_adapter_open_retries_network_failure():
    class Target:
        calls = 0
        def open(self):
            self.calls += 1
            if self.calls == 1:
                raise ConnectionError("temporary")
            return "chat"

    async def run():
        progress = _Progress(quiet=True)
        with patch("respan_redteam.cli.asyncio.sleep", return_value=None):
            assert await _open_adapter(Target(), 2, 1, progress) == "chat"

    asyncio.run(run())


def test_remote_connection_sends_bearer_api_key():
    async def run():
        connection = object()
        connect = AsyncMock(return_value=connection)
        with patch("websockets.connect", connect):
            result = await _connect(
                "wss://redteam.respan.ai/redteam/remote/",
                "secret-key",
                1,
                1,
                _Progress(quiet=True),
            )
        assert result is connection
        headers = connect.await_args.kwargs.get("additional_headers")
        if headers is None:
            headers = connect.await_args.kwargs["extra_headers"]
        assert headers == {"Authorization": "Bearer secret-key"}

    asyncio.run(run())


def test_credential_name_is_scoped_to_normalized_host():
    assert credential_name("wss://RedTeam.Respan.AI/redteam/remote/") == "redteam.respan.ai"


def test_api_key_resolution_prefers_flag_then_environment_then_keyring():
    with patch.dict(os.environ, {"RESPAN_API_KEY": "from-env"}, clear=True), \
         patch("respan_redteam.credentials.load_stored_api_key", return_value="stored"):
        assert resolve_api_key(DEFAULT_URL, "from-flag") == ("from-flag", "--api-key")
        assert resolve_api_key(DEFAULT_URL) == ("from-env", "environment")
    with patch.dict(os.environ, {}, clear=True), \
         patch("respan_redteam.credentials.load_stored_api_key", return_value="stored"):
        assert resolve_api_key(DEFAULT_URL) == ("stored", "system credential store")


def test_credential_save_rejects_a_backend_that_does_not_persist():
    with patch("respan_redteam.credentials.keyring.set_password"), \
         patch("respan_redteam.credentials.keyring.get_password", return_value=None):
        try:
            save_api_key(DEFAULT_URL, "secret")
            assert False, "expected a non-persisting credential backend to fail"
        except CredentialStoreUnavailable:
            pass


def test_auth_login_validates_before_saving_without_echoing_key():
    output = io.StringIO()
    with patch("respan_redteam.cli.getpass.getpass", return_value="secret-key"), \
         patch("respan_redteam.cli._validate_api_key", new=AsyncMock()), \
         patch("respan_redteam.cli.save_api_key") as save, redirect_stdout(output):
        assert _auth_main(["login", "--ws-url", DEFAULT_URL]) == 0
    save.assert_called_once_with(DEFAULT_URL, "secret-key")
    assert "secret-key" not in output.getvalue()
    assert "system credential store" in output.getvalue()


def test_auth_login_does_not_save_a_rejected_key():
    output = io.StringIO()
    rejected = AsyncMock(side_effect=RuntimeError("rejected"))
    with patch("respan_redteam.cli.getpass.getpass", return_value="bad-key"), \
         patch("respan_redteam.cli._validate_api_key", new=rejected), \
         patch("respan_redteam.cli.save_api_key") as save, redirect_stderr(output):
        assert _auth_main(["login", "--ws-url", DEFAULT_URL]) == 2
    save.assert_not_called()
    assert "bad-key" not in output.getvalue()


def test_auth_status_honors_environment_without_touching_keyring():
    output = io.StringIO()
    with patch.dict(os.environ, {"RESPAN_API_KEY": "secret"}, clear=True), \
         patch("respan_redteam.cli.load_stored_api_key") as load, redirect_stdout(output):
        assert _auth_main(["status"]) == 0
    load.assert_not_called()
    assert "configured in the environment" in output.getvalue()
    assert "secret" not in output.getvalue()


def test_validate_api_key_closes_the_authenticated_socket():
    async def run():
        connection = AsyncMock()
        with patch("respan_redteam.cli._connect", new=AsyncMock(return_value=connection)):
            await _validate_api_key(DEFAULT_URL, "secret")
        connection.close.assert_awaited_once()

    asyncio.run(run())


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    main()
