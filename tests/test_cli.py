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

from respan_redteam.cli import (_Progress, _CLI_THEME, _auth_main, _build_local_engine_config, _campaign_url,
                                _connect, _error, _explain,
                                _load_adapter, _open_adapter, _required,
                                _retryable_connection_error, _scan_main, _server_to_ws_url,
                                _validate_api_key, _write_report, main as cli_main)
from respan_redteam.credentials import (
    CredentialStoreUnavailable,
    credential_name,
    resolve_api_key,
    save_api_key,
)
from respan_redteam.user_config import ProfileConfig


def _progress(buf, *, terminal: bool = False, quiet: bool = False,
              probe_cap: int | None = None) -> _Progress:
    """A _Progress whose rich Console writes to `buf`."""
    console = Console(
        file=buf,
        force_terminal=terminal,
        no_color=not terminal,
        color_system="standard" if terminal else None,
        width=100,
        theme=_CLI_THEME,
    )
    return _Progress(console=console, quiet=quiet, probe_cap=probe_cap)


_EVENTS = [
    ("session.start", {"target": "acme"}),
    ("recon.profile.ready", {"target_type": "agent", "guardrail_strength": "high",
                             "extraction_confidence": 0.5, "detected_tools": [{"name": "fetch_url"}]}),
    ("category.start", {"phase": "breadth", "category": "LLM07", "goal": "leak"}),
    ("attack.attempt", {"technique": "seed:direct", "prompt": "hi"}),
    ("target.response", {"probes_used": 5, "snippet": "no"}),
    ("judge.verdict", {"outcome": "refused"}),
    ("attack.attempt", {"technique": "seed:roleplay", "prompt": "hi"}),
    ("judge.verdict", {"outcome": "success"}),
    ("finding.critical", {"title": "Secret", "severity": "critical"}),
    ("report.ready", {"grade": "F", "score": 40, "findings": 1, "probes": 12}),
]

DEFAULT_URL = "wss://redteam.respan.ai/redteam/remote/"


def test_progress_prints_every_event():
    buf = io.StringIO()
    p = _progress(buf, probe_cap=12)
    for e, d in _EVENTS:
        p.sink(e, d)
    p.close()
    out = buf.getvalue()
    # Off a TTY the dashboard degrades to durable milestones only — never per-probe
    # spam — while every counter is still tracked internally.
    assert "respan" in out and "acme" in out              # session banner
    assert "guardrail high" in out and "fetch_url" in out  # recon profile + tools
    assert "LLM07" in out                                 # category milestone
    assert "seed:direct" not in out                        # transient probe detail is not logged
    assert "Secret" in out and "critical" in out           # finding milestone
    assert "grade F" in out and "score 40" in out          # closing summary
    assert p.probes == 5 and p.breaches == 1 and p.findings == 1 and p.refused == 1


def test_quiet_emits_nothing():
    buf = io.StringIO()
    p = _progress(buf, quiet=True)
    for e, d in _EVENTS:
        p.sink(e, d)
    p.close()
    assert buf.getvalue() == ""


def test_strategy_error_is_readable():
    buf = io.StringIO()
    p = _progress(buf)
    raw = (
        "completion failed for gpt-4.1: Error code: 401 - "
        "{'error': {'message': 'Incorrect API key provided: not-required', "
        "'type': 'invalid_request_error', 'code': 'invalid_api_key'}}"
    )
    p.sink("strategy.error", {"strategy": "crescendo", "error": raw})
    p.close()
    out = buf.getvalue()
    assert "OPENAI_API_KEY" in out
    assert "Incorrect API key provided" not in out
    assert "invalid_api_key" not in out


def test_progress_interrupted_close_clears_and_shows_cursor():
    """Ctrl-C teardown must wipe the live region and un-hide the cursor."""
    buf = io.StringIO()
    # force_terminal alone still leaves TERM=dumb as a "dumb" console; give it a
    # real TERM so the live-dashboard path (and interrupt reset) engages.
    with patch.dict(os.environ, {"TERM": "xterm-256color"}):
        console = Console(
            file=buf,
            force_terminal=True,
            color_system="standard",
            width=100,
            theme=_CLI_THEME,
        )
        p = _Progress(console=console)
        assert p._tty
        p._ensure_live()
        p.close(interrupted=True)
    out = buf.getvalue()
    assert "\x1b[?25h" in out  # show cursor
    assert "\x1b[H" in out and "\x1b[2J" in out  # home + clear screen


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


def test_campaign_url_maps_hosted_api_to_web_console():
    assert _campaign_url(
        "wss://api.respan.ai/redteam/remote/", "a1b2"
    ) == "https://platform.respan.ai/platform/red/assessments?assessment=a1b2"
    assert _campaign_url(
        "wss://endpoint.respan.ai/redteam/remote/", "a1b2"
    ) == "https://enterprise.respan.ai/platform/red/assessments?assessment=a1b2"


def test_campaign_url_falls_back_to_same_origin_for_unmapped_hosts():
    assert _campaign_url(
        "wss://redteam.respan.ai/redteam/remote/", "campaign-1"
    ) == "https://redteam.respan.ai/campaign/campaign-1"
    assert _campaign_url(
        "ws://localhost:8000/redteam/remote/?token=x", "campaign-2"
    ) == "http://localhost:8000/campaign/campaign-2"


def test_server_origin_becomes_remote_websocket_endpoint():
    assert _server_to_ws_url("https://redteam.respan.ai") == DEFAULT_URL
    assert _server_to_ws_url("http://localhost:8000/") == (
        "ws://localhost:8000/redteam/remote/"
    )
    assert _server_to_ws_url("wss://example.com/custom") == "wss://example.com/custom/"


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


def test_auth_login_accepts_a_friendly_server_origin():
    with patch("respan_redteam.cli.getpass.getpass", return_value="secret-key"), \
         patch("respan_redteam.cli._validate_api_key", new=AsyncMock()) as validate, \
         patch("respan_redteam.cli.save_api_key") as save, redirect_stdout(io.StringIO()):
        assert _auth_main(["login", "--server", "https://redteam.respan.ai"]) == 0
    validate.assert_awaited_once_with(DEFAULT_URL, "secret-key")
    save.assert_called_once_with(DEFAULT_URL, "secret-key")


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


def test_main_routes_scan_command_and_legacy_adapter_invocation():
    with patch("respan_redteam.cli._scan_main", return_value=0) as scan:
        assert cli_main(["scan", "adapter.py"]) == 0
        scan.assert_called_once_with(["adapter.py"])
    with patch("respan_redteam.cli._scan_main", return_value=0) as scan:
        assert cli_main(["adapter.py", "--quiet"]) == 0
        scan.assert_called_once_with(["adapter.py", "--quiet"], legacy=True)


def test_main_without_arguments_prints_short_command_help():
    output = io.StringIO()
    with redirect_stdout(output):
        assert cli_main([]) == 0
    text = output.getvalue()
    assert "scan" in text and "auth" in text
    assert "tui-test" in text
    assert "--adapter-timeout" not in text


def test_tui_test_lists_modes_and_replays_errors():
    from respan_redteam.tui_test import main as tui_test_main, events_for, MODES

    assert set(MODES) >= {"ok", "errors", "breach", "full", "rate-limit"}
    listed = io.StringIO()
    with redirect_stdout(listed):
        assert tui_test_main(["--list"]) == 0
    assert "errors" in listed.getvalue() and "rate-limit" in listed.getvalue()

    names = [name for name, _ in events_for("errors") if name != "__note__"]
    assert "strategy.error" in names
    assert "report.ready" in names

    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        assert tui_test_main(["errors", "--fast", "--no-report"]) == 0
    assert "OPENAI_API_KEY" in err.getvalue()
    assert "strategy" in err.getvalue()


def test_tui_test_keyboard_interrupt_resets_and_exits_130():
    from respan_redteam.tui_test import run_tui_test

    err = io.StringIO()
    with redirect_stderr(err), patch("respan_redteam.tui_test._Progress") as ProgressCls:
        prog = ProgressCls.return_value
        prog.sink.side_effect = KeyboardInterrupt
        assert run_tui_test("ok", paced=False, write_report=False) == 130
        prog.close.assert_called_once_with(interrupted=True)
    assert "interrupted" in err.getvalue()


def test_tui_test_unknown_mode_fails():
    from respan_redteam.tui_test import main as tui_test_main

    err = io.StringIO()
    with redirect_stderr(err):
        try:
            tui_test_main(["not-a-mode", "--fast"])
            assert False, "expected unknown mode to fail"
        except SystemExit as exc:
            assert exc.code == 2
    assert "unknown tui-test mode" in err.getvalue()


def test_tui_test_routed_from_root():
    with patch("respan_redteam.tui_test.main", return_value=0) as tui:
        assert cli_main(["tui-test", "ok", "--no-report"]) == 0
        tui.assert_called_once_with(["ok", "--no-report"])


def test_scan_accepts_server_origin_and_runs_remote_adapter():
    target = type("Target", (), {"label": "test-agent"})()
    remote = AsyncMock(return_value=0)
    with patch("respan_redteam.cli._load_adapter", return_value=target), \
         patch("respan_redteam.cli.resolve_api_key", return_value=("secret", "test")) as auth, \
         patch("respan_redteam.cli._run_remote", new=remote):
        assert _scan_main([
            "adapter.py", "--server", "http://localhost:8000", "--quiet"
        ]) == 0
    auth.assert_called_once_with("ws://localhost:8000/redteam/remote/", None)
    assert remote.await_args.args[0] == "ws://localhost:8000/redteam/remote/"


def test_scan_without_credentials_points_to_auth_login():
    output = io.StringIO()
    with patch("respan_redteam.cli.resolve_api_key", return_value=(None, "none")), \
         redirect_stderr(output):
        try:
            _scan_main(["adapter.py"])
            assert False, "expected missing authentication to stop the scan"
        except SystemExit as exc:
            assert exc.code == 2
    assert "respan-redteam auth login" in output.getvalue()


def test_local_profile_owns_models_while_base_url_and_key_allow_environment():
    profile = ProfileConfig(
        name="local",
        mode="local",
        openai_base_url="http://localhost:11434/v1",
        model_attacker="attacker-model",
        budget={"max_target_probes": 12},
    )
    with (
        patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "environment-key",
                "RESPAN_MODEL_ATTACKER": "ignored-environment-model",
            },
            clear=True,
        ),
    ):
        config = _build_local_engine_config(profile)
        assert config.llm.api_key == "environment-key"
        assert config.llm.base_url == "http://localhost:11434/v1"
        assert config.llm.model_attacker == "attacker-model"
        assert config.budget.max_target_probes == 12


def test_local_profile_resets_unspecified_models_to_built_in_defaults():
    with patch.dict(os.environ, {"RESPAN_MODEL_ATTACKER": "ignored"}, clear=True):
        config = _build_local_engine_config(ProfileConfig(name="local", mode="local"))
        assert config.llm.model_attacker == "gpt-4.1"


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    main()
