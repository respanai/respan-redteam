"""Command-line entry point for the red-team engine.

    python -m respan_redteam --adapter ./adapter.py                 # remote scan (engine on redteam.respan.ai)
    python -m respan_redteam --adapter ./adapter.py --local         # run the engine on this machine
    python -m respan_redteam --adapter ./adapter.py --json > report.json
    python -m respan_redteam auth login                              # save a Respan API key

Point the engine at YOUR OWN agent via an adapter.py — a Target with `open() -> Chat` and
`chat.send(user_msg) -> str` (see target.py). A scan runs one of two ways:

  * REMOTE (default): the engine runs on redteam.respan.ai and exchanges chat messages with your
    local adapter over a WebSocket (override with `--ws-url`).
  * LOCAL (`--local`): the engine runs in-process on this machine (needs an OpenAI key).

Adapter examples are available at https://github.com/respanai/respan-redteam/tree/main/examples.

Progress streams every campaign event to stderr; the report is written to stdout, so
`... > report.json` stays clean. rich handles colour on a TTY (honours NO_COLOR / FORCE_COLOR).
Exit codes: 0 ok, 1 no report, 2 bad target/connect, 3 lost connection mid-campaign,
4 grade below --fail-under, 130 interrupted.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib.util
import inspect
import io
import json
import re
import os
import shlex
import subprocess
from pathlib import Path
import sys
import traceback
from urllib.parse import urlsplit, urlunsplit

from rich.console import Console
from rich.text import Text
from rich.theme import Theme
from dotenv import find_dotenv, load_dotenv

from . import DEFAULT_BUDGET, run_campaign
from .config import BudgetConfig, EngineConfig, LLMConfig
from .credentials import (
    CredentialStoreUnavailable,
    delete_api_key,
    load_stored_api_key,
    resolve_api_key,
    save_api_key,
)
from .model_client import TransientLLMError
from .user_config import (
    ProfileConfig,
    UserConfigError,
    config_path,
    load_profile,
    read_config,
    render_profile,
    selected_profile,
    set_profile_value,
    set_selected_profile,
    unset_profile_value,
    write_config,
)

load_dotenv(find_dotenv(usecwd=True) or find_dotenv(), override=False)

BUILTIN_SERVER = "https://redteam.respan.ai"
DEFAULT_SERVER = os.environ.get("RESPAN_REDTEAM_SERVER", BUILTIN_SERVER)
DEFAULT_WS_URL = os.environ.get("RESPAN_REDTEAM_WS_URL", "")
try:
    from importlib.metadata import version
    __version__ = version("respan-redteam")
except Exception:  # package metadata is optional in a source checkout
    __version__ = "0.1.3"

# Minimal theme for errors / progress (honours NO_COLOR / FORCE_COLOR via rich).
_CLI_THEME = Theme({
    "text": "#d4d4d4",
    "dim": "#737373",
    "bad": "#c47070",
    "warn": "#b8954a",
    "good": "#6f9f78",
})


def _console(*, stderr: bool = False, **kwargs) -> Console:
    """Console with the CLI theme; honours NO_COLOR / FORCE_COLOR via rich."""
    return Console(theme=_CLI_THEME, stderr=stderr, **kwargs)


def _clip(text: str, limit: int = 100) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _format_strategy_error(raw: str) -> str:
    """One readable line for strategy.error events (no raw JSON blobs)."""
    text = str(raw)
    low = text.lower()
    if "401" in text and ("invalid_api_key" in low or "incorrect api key" in low):
        return "attacker model auth failed (401) — check OPENAI_API_KEY"
    if "429" in text or "rate_limit" in low or "insufficient_quota" in low:
        return "attacker model rate limited — check quota or retry later"
    m = re.search(r"""['"]message['"]\s*:\s*['"]([^'"]+)['"]""", text)
    if m:
        return _clip(m.group(1), 90)
    m = re.search(r"Error code: \d+\s*[-—]\s*(.+)", text)
    if m:
        tail = m.group(1).strip()
        if tail.startswith("{") and (msg := re.search(r"""['"]message['"]\s*:\s*['"]([^'"]+)['"]""", tail)):
            return _clip(msg.group(1), 90)
        return _clip(tail, 90)
    return _clip(text, 100)


def _server_to_ws_url(server: str) -> str:
    """Accept a friendly HTTP origin or the legacy full WebSocket endpoint."""
    value = server.strip()
    parsed = urlsplit(value)
    if parsed.scheme in ("ws", "wss"):
        if not parsed.netloc:
            raise ValueError("server URL has no hostname")
        path = parsed.path or "/redteam/remote/"
        if not path.endswith("/"):
            path += "/"
        return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("server must be an http(s) or ws(s) URL")
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return urlunsplit((scheme, parsed.netloc, "/redteam/remote/", "", ""))


class _Progress:
    """Print every campaign event to stderr. No live bar; stdout stays free for the report."""

    def __init__(self, console: Console | None = None, quiet: bool = False,
                 probe_cap: int | None = None):
        self.console = console if console is not None else _console(stderr=True)
        self.quiet = quiet
        self.probe_cap = probe_cap
        self.probes = self.breaches = self.findings = self.refused = 0
        self._technique = "?"

    def line(self, text: str) -> None:
        if not self.quiet:
            self.console.print(text, soft_wrap=True, highlight=False)

    def note(self, text: str) -> None:
        """CLI-level status (connection, retries) — shown unless quiet."""
        self.line(f"note: {text}")

    def sink(self, event: str, data: dict) -> None:
        if self.quiet:
            return
        if event == "session.start":
            self.line(f"session.start  target={data.get('target', '?')}")
        elif event == "recon.probe.sent":
            self.line(
                f"recon.probe.sent  name={data.get('name', '?')}"
                f"  kind={data.get('kind', '?')}"
            )
        elif event == "recon.profile.ready":
            tools = ", ".join(x.get("name", "") for x in (data.get("detected_tools") or []))
            extra = f"  tools={tools}" if tools else ""
            self.line(
                f"recon.profile.ready  type={data.get('target_type', '?')}"
                f"  guardrail={data.get('guardrail_strength', '?')}"
                f"  extract={data.get('extraction_confidence', 0)}{extra}"
            )
        elif event == "category.start":
            goal = data.get("goal") or ""
            extra = f"  goal={goal}" if goal else ""
            self.line(
                f"category.start  phase={data.get('phase', '')}"
                f"  category={data.get('category', '')}{extra}"
            )
        elif event == "strategy.start":
            self.line(
                f"strategy.start  category={data.get('category', '')}"
                f"  strategy={data.get('strategy', '')}"
            )
        elif event == "strategy.error":
            self.line(
                f"strategy.error  strategy={data.get('strategy', '?')}"
                f"  error={_format_strategy_error(data.get('error', '?'))}"
            )
        elif event == "attack.attempt":
            self._technique = data.get("technique", "?")
            self.line(f"attack.attempt  technique={self._technique}")
        elif event == "target.response":
            if data.get("probes_used") is not None:
                self.probes = data["probes_used"]
            cap = f"/{self.probe_cap}" if self.probe_cap else ""
            snippet = " ".join(str(data.get("snippet") or "").split())
            if len(snippet) > 80:
                snippet = snippet[:79] + "…"
            extra = f"  snippet={snippet}" if snippet else ""
            self.line(f"target.response  probes={self.probes}{cap}{extra}")
        elif event == "judge.verdict":
            outcome = data.get("outcome", "")
            if outcome == "success":
                self.breaches += 1
            elif outcome == "refused":
                self.refused += 1
            self.line(f"judge.verdict  technique={self._technique}  outcome={outcome}")
        elif event == "finding.critical":
            self.findings += 1
            self.line(
                f"finding.critical  severity={data.get('severity', '?')}"
                f"  title={data.get('title', '')}"
            )
        elif event == "report.ready":
            self.line(
                f"report.ready  grade={data.get('grade', '?')}"
                f"  score={data.get('score', '?')}"
                f"  findings={data.get('findings', 0)}"
                f"  probes={data.get('probes', '?')}"
            )
        else:
            self.line(f"{event}  {data}")

    def close(self) -> None:
        pass


# --- remote adapter loading + WebSocket client -------------------------------
def _load_adapter(path: str, symbol: str | None = None):
    """Import the user's adapter module and resolve a Target that implements `.open() -> Chat`.
    Looked up in order: an explicit --symbol, then `TARGET`, `build_target()`, or `target`."""
    adapter_path = Path(path).expanduser()
    if not adapter_path.is_file():
        raise ValueError(f"adapter file not found: {adapter_path}")
    spec = importlib.util.spec_from_file_location("_respan_adapter", adapter_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load adapter from {path!r}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod          # register before exec so self-referential imports resolve
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(spec.name, None)  # don't leave a half-initialised module registered
        raise

    if symbol:
        obj = getattr(mod, symbol, None)
        if obj is None:
            raise ValueError(f"adapter has no symbol {symbol!r}")
        # a class or plain factory function is instantiated/called; an instance is used as-is
        tgt = obj() if inspect.isclass(obj) or inspect.isfunction(obj) else obj
    elif hasattr(mod, "TARGET"):
        tgt = mod.TARGET
    elif hasattr(mod, "build_target"):
        tgt = mod.build_target()
    elif hasattr(mod, "target"):
        tgt = mod.target
    else:
        raise ValueError("adapter must define TARGET, build_target(), or target")

    if not callable(getattr(tgt, "open", None)):
        raise ValueError("the adapter target must implement `.open() -> Chat` (see target.py / examples)")
    return tgt


def _explain(exc: BaseException) -> str:
    """Human-readable one-liner for a connection or engine failure (no traceback)."""
    import websockets.exceptions as we
    if isinstance(exc, we.InvalidStatus):
        status = getattr(exc.response, "status_code", "?")
        if status in (401, 403):
            return f"authentication failed (HTTP {status}) — run `respan-redteam auth login`"
        return f"server rejected the WebSocket (HTTP {status}) — check the --ws-url path"
    if isinstance(exc, we.InvalidURI):
        return "malformed --ws-url"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused — is the engine running at that URL?"
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timed out reaching the engine"
    if isinstance(exc, OSError):
        return f"network error ({exc})"
    if isinstance(exc, TransientLLMError):
        msg = str(exc)
        if "401" in msg or "invalid_api_key" in msg or "AuthenticationError" in msg:
            return "the OpenAI API rejected the key (401) — check OPENAI_API_KEY"
        if "429" in msg or "insufficient_quota" in msg:
            return "the OpenAI API is rate-limiting or out of quota — check your plan/usage"
        return f"the attacker/judge model failed repeatedly ({msg})"
    if isinstance(exc, (ValueError, RuntimeError)):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


def _error(title: str, exc: BaseException | None = None, *, hint: str | None = None,
           debug: bool = False) -> None:
    """Consistent, actionable stderr output with tracebacks only when requested (`--debug` or
    RESPAN_REDTEAM_DEBUG=1, so the top-level safety net can opt in without threading args
    through)."""
    console = _console(stderr=True)
    line = Text("error: ", style="bad")
    line.append(title)
    detail = _explain(exc) if exc is not None else ""
    if detail:
        line.append(f": {detail}")
    console.print(line, soft_wrap=True)
    if hint:
        hint_line = Text("hint: ", style="bold dim")
        hint_line.append(hint, style="dim")
        console.print(hint_line, soft_wrap=True)
    if exc is not None and (debug or os.environ.get("RESPAN_REDTEAM_DEBUG")):
        traceback.print_exception(exc, file=sys.stderr)


def _retryable_connection_error(exc: BaseException) -> bool:
    """Retry transport failures, throttling, and server errors—not bad URLs or auth failures."""
    import websockets.exceptions as we
    if isinstance(exc, we.InvalidURI):
        return False
    if isinstance(exc, we.InvalidStatus):
        status = getattr(exc.response, "status_code", 0)
        return status == 429 or status >= 500
    return isinstance(exc, (OSError, asyncio.TimeoutError, we.WebSocketException))


async def _connect(
    ws_url: str,
    api_key: str,
    retries: int,
    timeout: float,
    prog: _Progress,
):
    """Open the WebSocket with bounded exponential backoff. Raises the last error if exhausted."""
    import websockets
    from websockets.exceptions import WebSocketException
    delay, last = 1.0, None
    attempts = max(1, retries)
    header_argument = (
        "additional_headers"
        if int(websockets.__version__.split(".", maxsplit=1)[0]) >= 14
        else "extra_headers"
    )
    for attempt in range(1, attempts + 1):
        try:
            return await websockets.connect(
                ws_url,
                open_timeout=timeout,
                ping_interval=20,
                ping_timeout=60,
                max_size=None,
                **{header_argument: {"Authorization": f"Bearer {api_key}"}},
            )
        except (OSError, WebSocketException, asyncio.TimeoutError) as exc:
            last = exc
            if not _retryable_connection_error(exc):
                raise
            if attempt < attempts:
                prog.note(f"connect {attempt}/{attempts} failed ({_explain(exc)}); "
                          f"retrying in {delay:.0f}s")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 8.0)
    raise last  # type: ignore[misc]


async def _open_adapter(target, attempts: int, timeout: float, prog: _Progress):
    """Retry adapter session creation on immediate network failures; timed-out calls are not
    repeated because their worker thread may still complete in the background."""
    delay = 0.5
    for attempt in range(1, attempts + 1):
        try:
            return await asyncio.wait_for(asyncio.to_thread(target.open), timeout)
        except (ConnectionError, OSError) as exc:
            if attempt == attempts:
                raise
            prog.note(f"adapter open {attempt}/{attempts} failed ({_explain(exc)}); "
                      f"retrying in {delay:g}s")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 4.0)


def _required(msg: dict, *fields: str) -> None:
    missing = [field for field in fields if field not in msg]
    if missing:
        raise RuntimeError(f"remote {msg.get('op', 'message')} omitted {', '.join(missing)}")


def _campaign_url(ws_url: str, campaign_id: str) -> str:
    """Build the UI URL from a WebSocket endpoint without retaining its route path."""
    parsed = urlsplit(ws_url)
    scheme = "https" if parsed.scheme == "wss" else "http"
    origin = urlunsplit((scheme, parsed.netloc, "", "", ""))
    return f"{origin}/campaign/{campaign_id}"


def _write_report(report: dict, output_format: str, output: str | None = None) -> None:
    """Write exactly one report to stdout or a file; progress always remains on stderr. A
    completed campaign's data is never lost to a rendering bug: the text report is dry-run
    against a throwaway buffer first, falling back to plain JSON if that raises."""
    stream = None
    try:
        if output:
            path = Path(output).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            stream = path.open("w", encoding="utf-8")
        destination = stream or sys.stdout
        if output_format == "json":
            json.dump(report, destination, indent=2)
            destination.write("\n")
        else:
            try:
                _print_report(report, _console(file=io.StringIO(), force_terminal=False))
            except Exception as exc:  # noqa: BLE001 -- the campaign result matters more than the format
                print(f"warning: could not render the text report ({type(exc).__name__}: {exc});"
                     f" writing JSON instead", file=sys.stderr)
                json.dump(report, destination, indent=2)
                destination.write("\n")
            else:
                _print_report(report, _console(file=destination,
                                               force_terminal=False if stream else None))
    finally:
        if stream is not None:
            stream.close()


async def _run_remote(ws_url: str, api_key: str, target, output_format: str, output: str | None,
                      retries: int, connect_timeout: float, adapter_timeout: float,
                      adapter_retries: int, prog: _Progress,
                      fail_under: str | None = None) -> int:
    import websockets

    ws = await _connect(ws_url, api_key, retries, connect_timeout, prog)
    report, status, chats = None, "?", {}
    done_msg: dict = {}
    try:
        await ws.send(json.dumps({"op": "hello",
                                  "label": getattr(target, "label", "remote-target")}))
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except (json.JSONDecodeError, TypeError) as exc:
                raise RuntimeError("remote engine sent an invalid message") from exc
            if not isinstance(msg, dict) or not isinstance(msg.get("op"), str):
                raise RuntimeError("remote engine sent a malformed message")
            op = msg.get("op")
            if op == "ready":
                _required(msg, "campaign_id")
                cid = msg.get("campaign_id")
                prog.note(f"campaign running · progress at {_campaign_url(ws_url, str(cid))}")
            elif op == "open":
                _required(msg, "id", "chat_id")
                try:
                    # open() may do real I/O (login/handshake) — offload like send() so a slow
                    # open can't stall the event loop and starve the keepalive/read.
                    chats[msg["chat_id"]] = await _open_adapter(
                        target, adapter_retries, adapter_timeout, prog,
                    )
                    await ws.send(json.dumps({"id": msg["id"], "op": "result", "result": True}))
                except Exception as exc:  # noqa: BLE001 -- report the adapter error, keep serving
                    await ws.send(json.dumps({"id": msg["id"], "op": "error", "error": str(exc)}))
            elif op == "send":
                _required(msg, "id", "chat_id", "message")
                try:
                    chat = chats.get(msg.get("chat_id"))
                    if chat is None:
                        raise RuntimeError(f"unknown chat {msg.get('chat_id')}")
                    # Never retry sends: an ambiguous timeout may already have caused a tool action.
                    reply = await asyncio.wait_for(
                        asyncio.to_thread(chat.send, msg["message"]), adapter_timeout,
                    )
                    await ws.send(json.dumps({"id": msg["id"], "op": "result", "result": reply}))
                except Exception as exc:  # noqa: BLE001
                    await ws.send(json.dumps({"id": msg["id"], "op": "error", "error": str(exc)}))
            elif op == "event":
                prog.sink(msg.get("name", ""), msg.get("data") or {})
            elif op == "done":
                done_msg = msg
                report, status = msg.get("report"), msg.get("status", "?")
                break
            else:
                raise RuntimeError(f"remote engine sent unknown operation {op!r}")
    except websockets.ConnectionClosed as exc:
        prog.close()
        _error("lost connection to the remote engine mid-campaign", exc,
               hint="The campaign cannot safely replay agent actions; start a new run.")
        return 3
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass

    prog.close()
    if report is None:
        detail = f": {done_msg.get('error')}" if done_msg.get("error") else ""
        print(f"error: campaign ended without a report (status={status}{detail})", file=sys.stderr)
        return 1
    try:
        _write_report(report, output_format, output)
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1
    return _grade_exit_code(report.get("grade", "F"), fail_under)


_GRADE_RANK = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}


def _grade_exit_code(grade: str, fail_under: str | None) -> int:
    """0 normally; 4 when --fail-under was set and the achieved grade is below it (a CI gate)."""
    if fail_under and _GRADE_RANK.get(grade, 0) < _GRADE_RANK.get(fail_under, 5):
        return 4
    return 0


def _print_report(r: dict, console: Console) -> None:
    """Print the graded report as plain key=value lines."""
    findings = r.get("findings") or []
    findings_count = r.get("findings_count", len(findings))
    sev = r.get("severity_counts") or {}
    console.print(
        f"target={r.get('target_label', '?')}"
        f"  grade={r.get('grade', '?')}"
        f"  score={r.get('score', '?')}"
        f"  resistance={round((r.get('resistance_rate') or 0) * 100)}%"
        f"  findings={findings_count}"
        f"  probes={r.get('probes_sent', '?')}/{r.get('probes_total', '?')}"
        f"  cost=${r.get('cost_usd', '?')}"
        f"  duration={r.get('duration_s', '?')}s",
        highlight=False,
    )
    console.print(
        f"severity  critical={sev.get('critical', 0)}"
        f"  high={sev.get('high', 0)}"
        f"  medium={sev.get('medium', 0)}"
        f"  low={sev.get('low', 0)}",
        highlight=False,
    )
    if not findings:
        console.print("finding  (none)", highlight=False)
    for f in findings:
        evidence = _clip(f.get("evidence_span") or "", 100)
        parts = [
            f"finding  severity={f.get('severity', '?')}",
            f"title={f.get('title', '')}",
            f"category={f.get('category', '')}",
        ]
        if f.get("technique"):
            parts.append(f"technique={f['technique']}")
        if f.get("owasp"):
            parts.append(f"owasp={f['owasp']}")
        if f.get("atlas"):
            parts.append(f"atlas={f['atlas']}")
        if evidence:
            parts.append(f"evidence={evidence}")
        console.print("  ".join(parts), highlight=False)
    for t in sorted(r.get("category_tiles") or [], key=lambda x: x["category"]):
        if t.get("gateway_only"):
            console.print(
                f"category  id={t['category']}  name={t['name']}  access=gateway-only",
                highlight=False,
            )
        else:
            console.print(
                f"category  id={t['category']}  name={t['name']}"
                f"  grade={t.get('sub_grade', '?')}"
                f"  findings={t.get('findings', 0)}"
                f"  probes={t.get('probes_used', 0)}"
                f"  access=black-box",
                highlight=False,
            )


async def _validate_api_key(ws_url: str, api_key: str) -> None:
    connection = await _connect(
        ws_url,
        api_key,
        retries=1,
        timeout=15,
        prog=_Progress(quiet=True),
    )
    await connection.close()


def _auth_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="respan-redteam auth",
        description="Manage the Respan API key in your system credential store.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    descriptions = {
        "login": "validate and save an API key",
        "status": "show where the active API key comes from",
        "logout": "remove the saved API key",
    }
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument(
            "--server",
            default=None,
            metavar="URL",
            help=f"Respan server origin (default: {DEFAULT_SERVER})",
        )
        command.add_argument("--profile", metavar="NAME", help="configuration profile")
        command.add_argument(
            "--ws-url", dest="server", default=argparse.SUPPRESS, help=argparse.SUPPRESS
        )
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile)
        if profile.mode != "hosted":
            raise UserConfigError(
                f"profile {profile.name!r} is local; Respan authentication requires a hosted profile"
            )
        server = args.server or DEFAULT_WS_URL or os.environ.get(
            "RESPAN_REDTEAM_SERVER"
        ) or profile.server or BUILTIN_SERVER
        ws_url = _server_to_ws_url(server)
    except (ValueError, UserConfigError) as exc:
        parser.error(str(exc))

    if args.command == "login":
        try:
            api_key = getpass.getpass("Respan API key: ").strip()
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
        except EOFError:
            print("\nerror: no API key provided (stdin closed)", file=sys.stderr)
            return 2
        if not api_key:
            print("error: API key cannot be empty", file=sys.stderr)
            return 2
        try:
            asyncio.run(_validate_api_key(ws_url, api_key))
            save_api_key(ws_url, api_key)
        except CredentialStoreUnavailable:
            _error(
                "system credential store is unavailable",
                hint="Configure a system keyring or set RESPAN_API_KEY for this shell.",
            )
            return 2
        except Exception as exc:  # noqa: BLE001 -- auth/network errors are user-facing.
            _error("could not authenticate", exc, hint="Check the key and hosted engine URL.")
            return 2
        print("Authenticated. API key saved in the system credential store.")
        return 0

    try:
        if args.command == "status":
            environment = os.environ.get("RESPAN_API_KEY") or os.environ.get(
                "RESPAN_REDTEAM_API_KEY"
            )
            if environment:
                print("API key configured in the environment.")
                return 0
            stored = load_stored_api_key(ws_url)
            if stored:
                print("API key configured in the system credential store.")
                return 0
            print("Not authenticated. Run `respan-redteam auth login`.")
            return 1
        deleted = delete_api_key(ws_url)
    except CredentialStoreUnavailable:
        _error(
            "system credential store is unavailable",
            hint="Configure a system keyring or use RESPAN_API_KEY for this shell.",
        )
        return 2
    print("Logged out." if deleted else "No stored API key was found.")
    if os.environ.get("RESPAN_API_KEY") or os.environ.get("RESPAN_REDTEAM_API_KEY"):
        print("RESPAN_API_KEY remains set in the environment and still takes precedence.")
    return 0


def _config_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="respan-redteam config",
        description="Manage non-secret CLI profiles. API keys are never written here.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("path", help="print the configuration file path")
    show = commands.add_parser("show", help="show the effective profile")
    show.add_argument("--profile", metavar="NAME")
    use = commands.add_parser("use", help="select the default profile")
    use.add_argument("profile", metavar="NAME")
    set_command = commands.add_parser("set", help="set one profile value")
    set_command.add_argument("key", metavar="KEY")
    set_command.add_argument("value", metavar="VALUE")
    set_command.add_argument("--profile", metavar="NAME")
    unset = commands.add_parser("unset", help="remove one profile value")
    unset.add_argument("key", metavar="KEY")
    unset.add_argument("--profile", metavar="NAME")
    commands.add_parser("edit", help="open the TOML file in $VISUAL or $EDITOR")
    args = parser.parse_args(argv)

    if args.command == "path":
        print(config_path())
        return 0
    try:
        if args.command == "show":
            print(render_profile(load_profile(args.profile)), end="")
            print("# OPENAI_API_KEY: environment only")
            print("# RESPAN_API_KEY: environment or system credential store")
            return 0
        if args.command == "use":
            set_selected_profile(args.profile)
            print(f"Using profile {args.profile!r}.")
            return 0
        if args.command in ("set", "unset"):
            data = read_config()
            profile_name = args.profile or selected_profile(data)
            if args.command == "set":
                set_profile_value(profile_name, args.key, args.value)
                print(f"Set {args.key} in profile {profile_name!r}.")
            else:
                unset_profile_value(profile_name, args.key)
                print(f"Removed {args.key} from profile {profile_name!r}.")
            return 0
        path = config_path()
        if not path.exists():
            write_config(
                {
                    "profile": "default",
                    "profiles": {
                        "default": {"mode": "hosted", "server": DEFAULT_SERVER}
                    },
                }
            )
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if not editor:
            raise UserConfigError("set $VISUAL or $EDITOR before using `config edit`")
        try:
            command = shlex.split(editor)
        except ValueError as exc:  # unbalanced quotes in $VISUAL/$EDITOR
            _error(f"could not parse editor command {editor!r}", exc,
                   hint="Check the quoting in $VISUAL/$EDITOR.")
            return 2
        try:
            completed = subprocess.run([*command, str(path)], check=False)
        except OSError as exc:
            _error(f"could not launch editor {editor!r}", exc,
                   hint="Check that $VISUAL/$EDITOR points to an executable on your PATH.")
            return 2
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
        if completed.returncode != 0:
            return completed.returncode
        load_profile()
        return 0
    except UserConfigError as exc:
        _error("invalid configuration", exc, hint=f"Edit {config_path()} or run `config show`.")
        return 2


def _build_local_engine_config(profile: ProfileConfig) -> EngineConfig:
    llm_defaults = LLMConfig()
    values = {
        field_name: getattr(DEFAULT_BUDGET, field_name)
        for field_name in BudgetConfig.__dataclass_fields__
    }
    values.update(profile.budget)
    return EngineConfig(
        llm=LLMConfig(
            api_key=os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get("OPENAI_BASE_URL") or profile.openai_base_url,
            model_attacker=profile.model_attacker or llm_defaults.model_attacker,
            model_judge_gate=profile.model_judge_gate or llm_defaults.model_judge_gate,
            model_judge_grade=profile.model_judge_grade or llm_defaults.model_judge_grade,
            model_recon=profile.model_recon or llm_defaults.model_recon,
        ),
        budget=BudgetConfig(**values),
    )


def _scan_main(argv: list[str], *, legacy: bool = False) -> int:
    parser = argparse.ArgumentParser(
        prog="respan-redteam" if legacy else "respan-redteam scan",
        description="Run an autonomous red-team campaign against your own AI agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  respan-redteam scan adapter.py
  respan-redteam scan adapter.py --output report.json
  respan-redteam scan adapter.py --fail-under B
  respan-redteam scan adapter.py --local""",
    )
    parser.add_argument("adapter", nargs="?", metavar="ADAPTER",
                        help="Python file that connects the scanner to your agent")
    tgt = parser.add_argument_group("target — your agent")
    if legacy:
        tgt.add_argument("--adapter", dest="adapter_option", metavar="PATH",
                         help=argparse.SUPPRESS)
    else:
        parser.set_defaults(adapter_option=None)
    tgt.add_argument("-s", "--symbol", metavar="NAME",
                     help="name of the Target/factory in the adapter module (default: auto-detect)")
    tgt.add_argument("--profile", metavar="NAME", help="configuration profile")

    mode = parser.add_argument_group("execution")
    execution_mode = mode.add_mutually_exclusive_group()
    execution_mode.add_argument("-l", "--local", dest="local", action="store_true", default=None,
                      help="run the engine locally instead of using Respan's hosted engine")
    execution_mode.add_argument("--hosted", dest="local", action="store_false",
                                help="use Respan's hosted engine")
    mode.add_argument("--server", default=None, metavar="URL",
                      help=f"Respan server origin (default: {DEFAULT_SERVER})")
    mode.add_argument(
        "--ws-url", dest="server", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    mode.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="Respan API key for this scan (prefer auth login or RESPAN_API_KEY)",
    )
    mode.add_argument("--retries", type=int, default=3, metavar="N",
                      help=argparse.SUPPRESS)
    mode.add_argument("--connect-timeout", type=float, default=15, metavar="SECONDS",
                      help=argparse.SUPPRESS)
    mode.add_argument("--adapter-timeout", type=float, default=120, metavar="SECONDS",
                      help=argparse.SUPPRESS)
    mode.add_argument("--adapter-retries", type=int, default=2, metavar="N",
                      help=argparse.SUPPRESS)

    out = parser.add_argument_group("output")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="suppress progress; the final report is still written")
    out.add_argument("-f", "--format", choices=("text", "json"),
                     help="report format (default: text; inferred from a .json output path)")
    out.add_argument("--json", action="store_true",
                     help=argparse.SUPPRESS)
    out.add_argument("-o", "--output", metavar="PATH",
                     help="write the report to PATH instead of stdout; creates parent directories")
    out.add_argument("--fail-under", metavar="GRADE", choices=["A", "B", "C", "D", "F"],
                     help="exit 4 if the campaign grade is below GRADE (CI gate)")
    out.add_argument("--debug", action="store_true",
                     help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        profile = load_profile(args.profile)
    except UserConfigError as exc:
        parser.error(str(exc))
    if args.local is None:
        args.local = profile.mode == "local"

    if args.adapter and args.adapter_option:
        parser.error("pass the adapter once, either as ADAPTER or with --adapter")
    adapter = args.adapter_option or args.adapter
    if not adapter:
        parser.error("an adapter is required (respan-redteam scan adapter.py)")
    if args.retries < 1 or args.adapter_retries < 1:
        parser.error("--retries and --adapter-retries must be at least 1")
    if args.connect_timeout <= 0 or args.adapter_timeout <= 0:
        parser.error("timeouts must be greater than zero")
    if not args.local:
        try:
            server = args.server or DEFAULT_WS_URL or os.environ.get(
                "RESPAN_REDTEAM_SERVER"
            ) or profile.server or BUILTIN_SERVER
            args.ws_url = _server_to_ws_url(server)
        except ValueError as exc:
            parser.error(str(exc))
        args.api_key, _credential_source = resolve_api_key(args.ws_url, args.api_key)
        if not args.api_key:
            parser.error(
                "remote scans require authentication; run `respan-redteam auth login` "
                "or set RESPAN_API_KEY"
            )
    if args.json:
        if args.format is not None:
            parser.error("use either --json or --format, not both")
        args.format = "json"
    if args.format is None:
        args.format = (
            "json" if args.output and args.output.lower().endswith(".json")
            else profile.output_format or "text"
        )
    if args.fail_under is None:
        args.fail_under = profile.fail_under

    try:
        target = _load_adapter(adapter, args.symbol)
    except Exception as exc:  # noqa: BLE001 -- adapter import/factory failures are user-facing
        _error("could not load adapter", exc,
               hint="Check the path and ensure the module defines TARGET or build_target().",
               debug=args.debug)
        return 2

    local_config = _build_local_engine_config(profile) if args.local else None
    budget = local_config.budget if local_config is not None else DEFAULT_BUDGET
    prog = _Progress(quiet=args.quiet, probe_cap=budget.max_target_probes)

    # --- REMOTE scan (default): engine on the server, your agent on this machine (over WebSocket) ---
    if not args.local:
        prog.note(f"scan · {getattr(target, 'label', 'target')} → {args.ws_url}")
        try:
            return asyncio.run(_run_remote(
                args.ws_url, args.api_key, target, args.format, args.output, args.retries,
                args.connect_timeout, args.adapter_timeout, args.adapter_retries,
                prog, args.fail_under,
            ))
        except KeyboardInterrupt:
            prog.close()
            print("\ninterrupted", file=sys.stderr)
            return 130
        except Exception as exc:  # noqa: BLE001 -- connect exhausted / unexpected: no traceback
            prog.close()
            _error("could not run remote scan", exc,
                   hint="Check --server and network access; use --debug for adapter failures.",
                   debug=args.debug)
            return 2

    # --- LOCAL scan: run the engine in-process against the adapter ---
    assert local_config is not None
    try:
        result = run_campaign(target, config=local_config, sink=prog.sink)
    except KeyboardInterrupt:
        prog.close()
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 -- CLI failures should not dump a traceback
        prog.close()
        _error("local campaign failed", exc,
               hint="Verify OPENAI_API_KEY and your adapter; rerun with --debug for details.",
               debug=args.debug)
        return 1
    prog.close()
    report = result.to_report()
    try:
        _write_report(report, args.format, args.output)
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 1
    return _grade_exit_code(report["grade"], args.fail_under)


def _root_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="respan-redteam",
        description="Find security weaknesses in your AI agent with an adaptive attack campaign.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""quickstart:
  respan-redteam auth login
  respan-redteam scan adapter.py --output report.json

Run `respan-redteam <command> --help` for command-specific options.""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.add_parser("scan", add_help=False, help="run a red-team campaign")
    commands.add_parser("auth", add_help=False, help="manage your Respan API key")
    commands.add_parser("config", add_help=False, help="manage non-secret CLI profiles")
    commands.add_parser("tui-test", add_help=False,
                        help="replay a mock campaign through the progress printer")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        _root_parser().print_help()
        return 0
    try:
        if argv[0] == "scan":
            return _scan_main(argv[1:])
        if argv[0] == "auth":
            return _auth_main(argv[1:])
        if argv[0] == "config":
            return _config_main(argv[1:])
        if argv[0] == "tui-test":
            from .tui_test import main as tui_test_main
            return tui_test_main(argv[1:])
        if argv[0] in ("-h", "--help", "--version"):
            _root_parser().parse_args(argv)
            return 0
        # Backward compatibility for 0.1.x: `respan-redteam adapter.py [options]`.
        first = argv[0]
        if first.startswith("-") or first.endswith(".py") or Path(first).exists():
            return _scan_main(argv, legacy=True)
        _root_parser().error(
            f"unknown command {first!r}; choose `scan`, `auth`, `config`, or `tui-test`"
        )
        return 2
    except KeyboardInterrupt:
        # A last-resort net: the scan/auth paths already handle interrupts around their own I/O
        # (returning 130 there too); this only catches a Ctrl-C outside those windows (e.g. while
        # importing an adapter) so it never surfaces as a raw Python traceback.
        print("\ninterrupted", file=sys.stderr)
        return 130
    except SystemExit:
        raise   # argparse's normal --help/--version/parser.error() control flow
    except Exception as exc:  # noqa: BLE001 -- nothing should reach the user as a raw traceback
        _error("unexpected internal error", exc,
               hint="This looks like a bug in respan-redteam — please open an issue with "
                    "RESPAN_REDTEAM_DEBUG=1 output at "
                    "https://github.com/respanai/respan-redteam/issues.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
