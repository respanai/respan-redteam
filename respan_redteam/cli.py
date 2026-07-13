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

Progress + report render via rich (colour on a TTY; honours NO_COLOR / FORCE_COLOR). Progress
streams to stderr with a live counter; the report is written to stdout, so `... > report.json`
stays clean. Exit codes: 0 ok, 1 no report, 2 bad target/connect, 3 lost connection mid-campaign,
4 grade below --fail-under, 130 interrupted.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import traceback
from urllib.parse import urlsplit, urlunsplit

from rich import box
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from . import DEFAULT_BUDGET, run_campaign
from .credentials import (
    CredentialStoreUnavailable,
    delete_api_key,
    load_stored_api_key,
    resolve_api_key,
    save_api_key,
)

DEFAULT_WS_URL = os.environ.get(
    "RESPAN_REDTEAM_WS_URL", "wss://redteam.respan.ai/redteam/remote/",
)
try:
    from importlib.metadata import version
    __version__ = version("respan-redteam")
except Exception:  # package metadata is optional in a source checkout
    __version__ = "0.1.1"

# rich styles (rich itself handles terminal detection, NO_COLOR, and FORCE_COLOR).
_GRADE_STYLE = {"A": "bold green", "B": "green", "C": "bold yellow",
                "D": "red", "F": "bold red", "n/a": "dim"}
_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
_VERDICT_ICON = {"success": "✓", "partial": "~", "refused": "·", "error": "!"}


class _Progress:
    """Stream campaign progress to stderr via rich so stdout stays a clean report. Scrolling lines
    for phases/breaches/findings; on a terminal a one-line live counter tracks probes/breaches/
    refused/findings in place (refusals stay quiet). Piped, every verdict is logged for CI. rich
    handles terminal detection, NO_COLOR and FORCE_COLOR."""

    def __init__(self, console: Console | None = None, quiet: bool = False,
                 probe_cap: int | None = None):
        self.console = console if console is not None else Console(stderr=True)
        self.quiet = quiet
        self.probe_cap = probe_cap
        self.probes = self.breaches = self.findings = self.refused = 0
        self.phase = "starting"
        self._technique = "?"      # tracked from attack.attempt; labels the following verdict
        self._live: Live | None = None

    def _status(self) -> Text:
        cap = f"/{self.probe_cap}" if self.probe_cap else ""
        t = Text("  ")
        t.append(self.phase, style="bold cyan")
        t.append(f" · probes {self.probes}{cap} · breaches ")
        t.append(str(self.breaches), style="bold yellow")
        t.append(f" · refused {self.refused} · findings ")
        t.append(str(self.findings), style="bold red")
        return t

    def _ensure_live(self) -> None:
        # a live in-place counter, only on an interactive terminal
        if self._live is None and not self.quiet and self.console.is_terminal:
            self._live = Live(self._status(), console=self.console,
                              transient=True, auto_refresh=False)
            self._live.start()

    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._status(), refresh=True)

    def line(self, renderable) -> None:
        if not self.quiet:
            self.console.print(renderable, soft_wrap=True)   # rich prints above the live region

    def note(self, text: str) -> None:
        """CLI-level status (connection, retries) — dim, shown unless quiet."""
        self.line(Text(f"[remote] {text}", style="dim"))

    def sink(self, event: str, data: dict) -> None:
        if self.quiet:
            return
        self._ensure_live()
        if event == "session.start":
            self.line(Text(f"▸ target: {data.get('target', '?')}", style="bold"))
        elif event == "recon.probe.sent":
            self.phase = "recon"
            self._refresh()
        elif event == "recon.profile.ready":
            tools = ", ".join(t.get("name", "") for t in (data.get("detected_tools") or []))
            self.phase = "recon done"
            line = Text("◆ recon", style="magenta")
            line.append(f"  type={data.get('target_type', '?')}"
                        f"  guardrail={data.get('guardrail_strength', '?')}"
                        f"  extract={data.get('extraction_confidence', 0)}"
                        + (f"  tools=[{tools}]" if tools else ""))
            self.line(line)
        elif event == "category.start":
            self.phase = " ".join(x for x in (data.get("phase"), data.get("category")) if x)
            label = " · ".join(x for x in (data.get("phase"), data.get("category"),
                                           data.get("goal")) if x)
            self.line(Text(f"▸ {label}", style="bold cyan"))
        elif event == "strategy.start":
            self.line(Text(f"  → {data.get('strategy', '')}", style="dim"))
        elif event == "attack.attempt":
            self._technique = data.get("technique", "?")   # remembered for the following verdict
        elif event == "target.response":
            if data.get("probes_used") is not None:
                self.probes = data["probes_used"]
            self._refresh()
        elif event == "judge.verdict":
            outcome = data.get("outcome", "")
            tech = self._technique
            icon = _VERDICT_ICON.get(outcome, "·")
            if outcome == "success":
                self.breaches += 1
                self.line(Text(f"  {icon} {tech}  BREACH", style="bold yellow"))
            else:
                if outcome == "refused":
                    self.refused += 1
                if self._live is not None:
                    self._refresh()          # the live counter carries refusals
                else:
                    self.line(Text(f"  {icon} {tech}  {outcome}", style="dim"))   # piped: full log
        elif event == "finding.critical":
            self.findings += 1
            self.line(Text(f"★ FINDING [{data.get('severity', '?')}] {data.get('title', '')}",
                           style="bold red"))
        elif event == "report.ready":
            self.phase = "done"
            self.line(Text(f"✔ complete · grade {data.get('grade', '?')}"
                           f" · score {data.get('score', '?')}/100"
                           f" · {data.get('findings', 0)} findings"
                           f" · {data.get('probes', '?')} probes", style="bold green"))

    def close(self) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None


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
    """Human-readable one-liner for a connection failure (no traceback)."""
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
    if isinstance(exc, (ValueError, RuntimeError)):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


def _error(title: str, exc: BaseException | None = None, *, hint: str | None = None,
           debug: bool = False) -> None:
    """Consistent, actionable stderr output with tracebacks only when requested."""
    detail = _explain(exc) if exc is not None else ""
    print(f"error: {title}{': ' + detail if detail else ''}", file=sys.stderr)
    if hint:
        print(f"hint: {hint}", file=sys.stderr)
    if debug and exc is not None:
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
    """Write exactly one report to stdout or a file; progress always remains on stderr."""
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
            _print_report(report, Console(file=destination, force_terminal=False if stream else None))
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
    """Render the graded report to `console` (rich Table + styled lines). When stdout is piped
    (`> report.txt`) rich drops colour automatically; `--json` is emitted separately."""
    console.rule(Text(f"Respan red-team · {r['target_label']}", style="bold"))

    grade = Text("Grade ")
    grade.append(r["grade"], style=_GRADE_STYLE.get(r["grade"], ""))
    grade.append(f"  ·  score {r['score']}/100  ·  resistance {round(r['resistance_rate'] * 100)}%")
    console.print(grade)
    console.print(f"Probes {r['probes_sent']}/{r['probes_total']}  ·  cost ${r['cost_usd']}"
                  f"  ·  {r['duration_s']}s", style="dim")
    sev = Text("Severity ")
    counts = [(k, v) for k, v in r["severity_counts"].items() if v]
    for i, (k, v) in enumerate(counts):
        sev.append("  " if i else "")
        sev.append(f"{k} {v}", style=_SEV_STYLE.get(k, ""))
    if not counts:
        sev.append("none", style="dim")
    console.print(sev)

    # per-category report card — the full picture, not just the breaches
    tiles = sorted(r.get("category_tiles") or [], key=lambda t: t["category"])
    if tiles:
        table = Table(box=box.SIMPLE_HEAD, title="Category card", title_justify="left",
                      title_style="bold", pad_edge=False, show_edge=False)
        table.add_column("", justify="right")
        table.add_column("cat", style="bold")
        table.add_column("category")
        table.add_column("result", style="dim")
        for t in tiles:
            if t.get("gateway_only"):
                table.add_row(Text("·", style="dim"), t["category"], t["name"],
                              Text("gateway-only — needs deeper access", style="dim"))
            else:
                n, p = t["findings"], t["probes_used"]
                table.add_row(Text(t["sub_grade"], style=_GRADE_STYLE.get(t["sub_grade"], "")),
                              t["category"], t["name"],
                              f"{n} finding{'s' * (n != 1)} · {p} probe{'s' * (p != 1)}")
        console.print(table)

    console.print(Text(f"Findings ({r['findings_count']})", style="bold"))
    if not r["findings"]:
        console.print(Text("  none — target held.", style="dim"))
    for f in r["findings"]:
        head = Text("  ")
        head.append(f"[{f['severity']:>8}]", style=_SEV_STYLE.get(f["severity"], ""))
        head.append(" ")
        head.append(f["category"], style="bold")
        head.append("  ")
        head.append(f["title"])                            # user content: no markup parsing (Text.append)
        console.print(head, soft_wrap=True)
        console.print(Text(f"    via {f['technique']}", style="dim"))
        if f.get("evidence_span"):
            console.print(Text(f"    “{f['evidence_span'][:120]}”", style="dim"), soft_wrap=True)


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
    for name in ("login", "status", "logout"):
        command = commands.add_parser(name)
        command.add_argument(
            "--ws-url",
            default=DEFAULT_WS_URL,
            metavar="URL",
            help=f"hosted engine WebSocket URL (default: {DEFAULT_WS_URL})",
        )
    args = parser.parse_args(argv)

    if args.command == "login":
        api_key = getpass.getpass("Respan API key: ").strip()
        if not api_key:
            print("error: API key cannot be empty", file=sys.stderr)
            return 2
        try:
            asyncio.run(_validate_api_key(args.ws_url, api_key))
            save_api_key(args.ws_url, api_key)
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
            stored = load_stored_api_key(args.ws_url)
            if stored:
                print("API key configured in the system credential store.")
                return 0
            print("Not authenticated. Run `respan-redteam auth login`.")
            return 1
        deleted = delete_api_key(args.ws_url)
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


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "auth":
        return _auth_main(argv[1:])
    parser = argparse.ArgumentParser(
        prog="respan-redteam",
        description="Run an autonomous red-team campaign against your own AI agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  respan-redteam auth login
  respan-redteam ./adapter.py
  respan-redteam ./adapter.py --local
  respan-redteam ./adapter.py -f json -o report.json
  respan-redteam ./adapter.py --fail-under B

No adapter yet? See https://redteam.respan.ai/setup.txt""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("adapter", nargs="?", metavar="ADAPTER",
                        help="path to adapter.py (may also be passed with --adapter)")
    tgt = parser.add_argument_group("target — your agent")
    tgt.add_argument("--adapter", dest="adapter_option", metavar="PATH",
                     help="path to your adapter.py: a Target with .open() -> Chat")
    tgt.add_argument("-s", "--symbol", metavar="NAME",
                     help="name of the Target/factory in the adapter module (default: auto-detect)")

    mode = parser.add_argument_group("scan mode")
    mode.add_argument("-l", "--local", action="store_true",
                      help="run the engine in-process on this machine (needs an OpenAI key). Default "
                           "is a REMOTE scan: the engine exchanges chat messages with your local "
                           "adapter over a WebSocket.")
    mode.add_argument("--ws-url", dest="ws_url", default=DEFAULT_WS_URL, metavar="URL",
                      help=f"remote-scan engine WebSocket URL (default: {DEFAULT_WS_URL})")
    mode.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="Respan API key for this scan (prefer auth login or RESPAN_API_KEY)",
    )
    mode.add_argument("--retries", type=int, default=3, metavar="N",
                      help="remote connection attempts with backoff; must be >= 1 (default: 3)")
    mode.add_argument("--connect-timeout", type=float, default=15, metavar="SECONDS",
                      help="timeout for each remote connection attempt (default: 15)")
    mode.add_argument("--adapter-timeout", type=float, default=120, metavar="SECONDS",
                      help="timeout for adapter open/send calls (default: 120)")
    mode.add_argument("--adapter-retries", type=int, default=2, metavar="N",
                      help="adapter open attempts; sends are never replayed (default: 2)")

    out = parser.add_argument_group("output")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="suppress progress; the final report is still written")
    out.add_argument("-f", "--format", choices=("text", "json"),
                     help="report format (default: text; inferred from a .json output path)")
    out.add_argument("--json", action="store_true",
                     help="shortcut for --format json (kept for compatibility)")
    out.add_argument("-o", "--output", metavar="PATH",
                     help="write the report to PATH instead of stdout; creates parent directories")
    out.add_argument("--fail-under", metavar="GRADE", choices=["A", "B", "C", "D", "F"],
                     help="exit 4 if the campaign grade is below GRADE (CI gate)")
    out.add_argument("--debug", action="store_true",
                     help="include a traceback for unexpected local CLI failures")
    args = parser.parse_args(argv)

    if args.adapter and args.adapter_option:
        parser.error("pass the adapter once, either as ADAPTER or with --adapter")
    adapter = args.adapter_option or args.adapter
    if not adapter:
        parser.error("an adapter is required (respan-redteam ./adapter.py)")
    if args.retries < 1 or args.adapter_retries < 1:
        parser.error("--retries and --adapter-retries must be at least 1")
    if args.connect_timeout <= 0 or args.adapter_timeout <= 0:
        parser.error("timeouts must be greater than zero")
    if not args.local:
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
        args.format = "json" if args.output and args.output.lower().endswith(".json") else "text"

    try:
        target = _load_adapter(adapter, args.symbol)
    except Exception as exc:  # noqa: BLE001 -- adapter import/factory failures are user-facing
        _error("could not load adapter", exc,
               hint="Check the path and ensure the module defines TARGET or build_target().",
               debug=args.debug)
        return 2

    prog = _Progress(quiet=args.quiet, probe_cap=DEFAULT_BUDGET.max_target_probes)

    # --- REMOTE scan (default): engine on the server, your agent on this machine (over WebSocket) ---
    if not args.local:
        prog.note(f"remote scan · {getattr(target, 'label', 'target')} → {args.ws_url}")
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
                   hint="Check --ws-url and network access; use --debug for adapter failures.",
                   debug=args.debug)
            return 2

    # --- LOCAL scan: run the engine in-process against the adapter ---
    try:
        result = run_campaign(target, sink=prog.sink)
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


if __name__ == "__main__":
    sys.exit(main())
