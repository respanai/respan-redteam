"""The red-team terminal UI — the live campaign dashboard and the graded report card.

Two surfaces, one visual language (Respan branding: near-black, monospace, muted
accents, dim section labels, no full-width rules):

  * `_Progress` renders a running campaign to stderr as a fixed, live-updating
    dashboard on a TTY — the terminal twin of the web run view. Transient detail
    (the current attack, recon intel) is replaced in place; only findings accumulate.
    Off a TTY (pipe / CI) or under --quiet it degrades to a few milestone lines, so
    stdout is always free for the report.
  * `_print_report` renders the final `CampaignResult` report dict as a graded card:
    a grade badge, severity spread, OWASP coverage spine, and finding detail.

Only `rich` is used, so both surfaces render as clean monospace text (colour stripped)
when written to a file or a pipe.
"""

from __future__ import annotations

import time

from rich.box import ROUNDED
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text
from rich.theme import Theme

# --- brand palette -----------------------------------------------------------
# Muted, desaturated accents pulled from the Respan product UI. `text`/`dim`/`faint`
# carry the neutral spine; the coloured styles mark verdicts, severities, and grades.
THEME = Theme(
    {
        "text": "#d4d4d4",
        "dim": "#737373",
        "faint": "#4a4a4a",
        "brand": "#6cb6c9",  # the product's cyan/teal accent
        "good": "#6f9f78",  # target held / grade A
        "warn": "#b8954a",  # partial / errors
        "bad": "#c47070",  # breach / grade F
        # severities
        "crit": "#c05b5b",
        "high": "#c47070",
        "med": "#b8954a",
        "low": "#7f8fa6",
    }
)

_MARK = "[⢀]"  # the Respan wordmark, rendered with a Braille dot (U+2880)
# Bracketed Braille spinner frames — the wordmark "loading" while a campaign runs.
# A 6-dot snake confined to the BOTTOM three rows of the cell, so it sits on the text
# baseline (like the [⢀] mark) instead of floating at the top.
_SPIN_FRAMES = [f"[{c}]" for c in "⠖⠲⢲⢰⣰⣠⣄⣆⡆⡖"]

# verdict -> (glyph, style, label). A refusal is a win for the *target*, hence green.
_VERDICT = {
    "refused": ("✓", "good", "refused"),
    "success": ("✗", "bad", "breach"),
    "partial": ("~", "warn", "partial"),
    "error": ("!", "warn", "error"),
}

_SEV_STYLE = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}
_GRADE_STYLE = {"A": "good", "B": "brand", "C": "warn", "D": "warn", "F": "bad"}


def _console(*, stderr: bool = False, **kwargs) -> Console:
    """Console with the brand theme; honours NO_COLOR / FORCE_COLOR via rich."""
    return Console(theme=THEME, stderr=stderr, **kwargs)


def _clip(text: str, limit: int = 100) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _format_strategy_error(raw: str) -> str:
    """One readable line for strategy.error events (no raw JSON blobs)."""
    import re

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
        if tail.startswith("{") and (
            msg := re.search(r"""['"]message['"]\s*:\s*['"]([^'"]+)['"]""", tail)
        ):
            return _clip(msg.group(1), 90)
        return _clip(tail, 90)
    return _clip(text, 100)


# --- small render helpers ----------------------------------------------------
def _section(label: str) -> Text:
    """A plain, dim section label (no full-width rule)."""
    return Text(f"  {label}", style="dim")


def _finding_title(sev: str, title: str) -> Text:
    """A finding's headline row — identical in the live view and the report card."""
    line = Text("   ")
    line.append(f"{sev:<9}", style=_SEV_STYLE.get(sev, "crit"))
    line.append(str(title), style="text")
    return line


def _pct(value) -> str:
    try:
        return f"{round(float(value) * 100)}%"
    except (TypeError, ValueError):
        return "?"


# Campaign phases, in order, for the segmented phase bar (mirrors the web frontend).
_PHASES = [
    ("recon", "Recon"),
    ("breadth", "Breadth"),
    ("depth", "Depth"),
    ("verify", "Verification"),
    ("report", "Report"),
]
_PHASE_INDEX = {"recon": 0, "breadth": 1, "depth": 2, "verify": 3, "report": 4}


def _preview(text, limit: int = 62) -> str:
    text = " ".join(str(text or "").split())
    if not text:
        return "—"
    return text if len(text) <= limit else text[: limit - 1] + "…"


class _Progress:
    """Render a campaign as a fixed, live-updating dashboard on a TTY — the terminal
    twin of the web run view.

    Transient detail (the current attack, recon intel) is *replaced in place*; only
    durable events (findings) accumulate, so the view stays calm no matter how many
    probes fly by. stdout is never touched, so `... > report.json` stays clean. Off a
    TTY (pipe / CI) or under --quiet it degrades to a few milestone lines: session,
    recon profile, each category, each finding, and the final grade — never per-probe
    spam. The final report card prints separately once the campaign ends.
    """

    def __init__(
        self,
        console: Console | None = None,
        quiet: bool = False,
        probe_cap: int | None = None,
    ):
        self.console = console if console is not None else _console(stderr=True)
        self.quiet = quiet
        self.probe_cap = probe_cap
        self.probes = self.breaches = self.findings = self.refused = 0
        self._live = None
        self._closed = False
        self._saved_width = None
        self._t0 = time.monotonic()
        # Live dashboard only on a real interactive TTY. force_terminal / FORCE_COLOR can
        # make is_terminal True for pipes; those are still "dumb" and should get milestones.
        self._tty = (
            bool(self.console.is_terminal)
            and not self.console.is_dumb_terminal
            and not quiet
        )
        self._spinner = Spinner(
            "dots", style="brand"
        )  # Braille loading mark while running
        self._spinner.frames = _SPIN_FRAMES
        # dashboard state
        self._target = "campaign"
        self._status = "running"
        self._phase_idx = -1
        self._categories = 0
        self._conn = ""
        self._message = ""
        # current attempt (transient)
        self._cur_category = ""
        self._cur_goal = ""
        self._cur_strategy = ""
        self._cur_technique = ""
        self._cur_prompt = ""
        self._cur_response = ""
        # recon / target intelligence (set once, then stable)
        self._intel_type = ""
        self._intel_guard = ""
        self._intel_extract = None
        self._intel_tools = ""
        # durable findings, newest last
        self._finding_rows: list[tuple[str, str]] = []

    # -- output plumbing ------------------------------------------------------
    def _ensure_live(self) -> None:
        if self._live is None and self._tty:
            from rich.live import Live

            # Reserve a 2-col right margin: the Braille wordmark/spinner is width-1 to
            # rich but many terminal fonts render Braille double-width, so a full-width
            # padded line would overflow by a cell, wrap, and smear the live redraw.
            self._saved_width = self.console._width
            self.console._width = max(24, self.console.size.width - 2)
            self._live = Live(
                self._dash(),
                console=self.console,
                refresh_per_second=12,
                transient=True,
            )
            try:
                self._live.start()
            except (
                Exception
            ):  # noqa: BLE001 -- a Live that won't start must not sink the scan
                self._live = None
                self._restore_width()

    def _restore_width(self) -> None:
        self.console._width = self._saved_width

    def _refresh(self) -> None:
        if self._live is not None:
            try:
                self._live.update(self._dash())
            except Exception:  # noqa: BLE001
                pass

    def _milestone(self, *renderables) -> None:
        """A durable line printed only off a TTY (on a TTY it lives in the dashboard)."""
        if self._tty or self.quiet:
            return
        for r in renderables:
            self.console.print(r, soft_wrap=True, highlight=False)

    # -- dashboard renderable -------------------------------------------------
    def _phase_bar(self) -> Text:
        bar = Text("  ")
        for i, (_key, label) in enumerate(_PHASES):
            if i:
                bar.append("   ", style="faint")
            if i < self._phase_idx:
                bar.append(label, style="dim")
            elif i == self._phase_idx:
                bar.append(label, style="brand bold")
            else:
                bar.append(label, style="faint")
        return bar

    def _stat_row(self) -> Text:
        row = Text("  ")

        def stat(label: str, value, vstyle: str = "text", pad: str = "    ") -> None:
            row.append(f"{label} ", style="dim")
            row.append(str(value), style=vstyle)
            row.append(pad)

        probes = (
            f"{self.probes}/{self.probe_cap}" if self.probe_cap else str(self.probes)
        )
        elapsed = int(time.monotonic() - self._t0)
        stat("probes", probes)
        stat("elapsed", f"{elapsed // 60}:{elapsed % 60:02d}")
        stat("categories", self._categories)
        stat("findings", self.findings, "warn" if self.findings else "text", "")
        return row

    def _kv(self, key: str, value, vstyle: str = "text") -> Text:
        line = Text("    ")
        line.append(f"{key:<13}", style="dim")
        line.append(str(value), style=vstyle)
        return line

    def _dash(self):
        from rich.console import Group

        htext = Text(self._target, style="text")
        if self._status == "running":
            # a live Braille spinner stands in for the wordmark while the campaign runs
            self._spinner.update(text=htext)
            head = Padding(self._spinner, (0, 0, 0, 2))
        else:
            head = Text("  ")
            head.append(_MARK, style="brand")
            head.append(" ")
            head.append_text(htext)

        parts = [head, Text(""), self._phase_bar(), Text(""), self._stat_row()]
        if self._message:
            msg = Text("  ")
            msg.append(self._message, style="warn")
            parts += [Text(""), msg]

        # current attempt (replaced live)
        parts += [Text(""), Text("  current attempt", style="dim")]
        if self._cur_technique or self._cur_goal:
            head2 = Text("    ")
            head2.append(self._cur_category or "—", style="brand")
            if self._cur_goal:
                head2.append(f"  {self._cur_goal}", style="text")
            parts.append(head2)
            tech = self._cur_technique or "—"
            if self._cur_strategy and self._cur_strategy not in ("breadth", ""):
                tech = f"{tech}   ({self._cur_strategy})"
            parts.append(self._kv("technique", tech))
            parts.append(self._kv("prompt", _preview(self._cur_prompt), "text"))
            parts.append(self._kv("response", _preview(self._cur_response), "text"))
        else:
            parts.append(Text("    waiting for the first attempt…", style="faint"))

        # target intelligence (from recon, stable once known)
        parts += [Text(""), Text("  target intelligence", style="dim")]
        parts.append(
            self._kv(
                "profile",
                self._intel_type or "—",
                "text" if self._intel_type else "faint",
            )
        )
        if self._intel_guard or self._intel_extract is not None:
            defenses = f"guardrail {self._intel_guard or '?'}"
            if self._intel_extract is not None:
                defenses += f" · extraction {_pct(self._intel_extract)}"
            parts.append(self._kv("defenses", defenses))
        else:
            parts.append(self._kv("defenses", "—", "faint"))
        parts.append(
            self._kv(
                "capabilities",
                self._intel_tools or "—",
                "text" if self._intel_tools else "faint",
            )
        )

        # findings (durable — the only list that grows). Same headline row as the report.
        if self._finding_rows:
            parts += [Text(""), _section("findings")]
            for sev, title in self._finding_rows:
                parts.append(_finding_title(sev, title))

        # connection / campaign-link footer (where the "Available at" URL lands).
        # Aligned with the section labels; clipped to the render width so a long URL
        # can't wrap and smear the live redraw.
        if self._conn:
            foot = Text("  ")
            foot.append(
                _preview(self._conn, max(20, self.console.width - 4)), style="dim"
            )
            parts += [Text(""), foot]

        return Group(*parts)

    # -- CLI-level notes ------------------------------------------------------
    def note(self, text: str) -> None:
        """Connection / retry status. Updates the dashboard's connection field on a TTY;
        prints a dim milestone line off one."""
        self._ensure_live()
        self._conn = str(text)
        self._refresh()
        line = Text("  · ", style="faint")
        line.append(str(text), style="dim")
        self._milestone(line)

    # -- event sink -----------------------------------------------------------
    def sink(self, event: str, data: dict) -> None:
        if self.quiet:
            return
        self._ensure_live()
        handler = getattr(self, f"_on_{event.replace('.', '_')}", None)
        if handler is not None:
            handler(data)
        self._refresh()

    def _advance(self, key: str) -> None:
        self._phase_idx = max(self._phase_idx, _PHASE_INDEX.get(key, self._phase_idx))

    def _on_session_start(self, data: dict) -> None:
        self._target = str(data.get("target", "target"))
        self._advance("recon")
        head = Text("  ")
        head.append(_MARK, style="brand")
        head.append(" respan ", style="text")
        head.append("redteam · ", style="dim")
        head.append(self._target, style="text")
        self._milestone(head)

    def _on_recon_profile_ready(self, data: dict) -> None:
        self._advance("recon")
        self._intel_type = str(data.get("target_type", ""))
        self._intel_guard = str(data.get("guardrail_strength", ""))
        self._intel_extract = data.get("extraction_confidence")
        self._intel_tools = ", ".join(
            x.get("name", "") for x in (data.get("detected_tools") or [])
        )
        line = Text("  recon  ", style="dim")
        line.append(self._intel_type or "?", style="text")
        line.append(f"  guardrail {self._intel_guard or '?'}", style="text")
        if self._intel_extract is not None:
            line.append(f"  extraction {_pct(self._intel_extract)}", style="text")
        if self._intel_tools:
            line.append(f"  tools {self._intel_tools}", style="dim")
        self._milestone(line)

    def _on_category_start(self, data: dict) -> None:
        phase = str(data.get("phase", ""))
        self._advance(phase)
        self._categories += 1
        self._cur_category = str(data.get("category", ""))
        self._cur_goal = str(data.get("goal") or "")
        self._cur_strategy = ""
        self._cur_technique = self._cur_prompt = self._cur_response = ""
        line = Text(f"  {phase or 'phase'}  ", style="dim")
        line.append(self._cur_category, style="brand")
        if self._cur_goal:
            line.append(f"  {self._cur_goal}", style="text")
        self._milestone(line)

    def _on_strategy_start(self, data: dict) -> None:
        self._cur_strategy = str(data.get("strategy", ""))

    def _on_strategy_error(self, data: dict) -> None:
        self._message = _format_strategy_error(data.get("error", "?"))
        line = Text("  ! strategy  ", style="warn")
        line.append(self._message, style="warn")
        self._milestone(line)

    def _on_attack_attempt(self, data: dict) -> None:
        self._cur_technique = str(data.get("technique", "?"))
        self._cur_prompt = str(data.get("prompt", ""))
        self._cur_response = ""

    def _on_target_response(self, data: dict) -> None:
        if data.get("probes_used") is not None:
            self.probes = int(data["probes_used"])
        self._cur_response = str(data.get("snippet", ""))

    def _on_judge_verdict(self, data: dict) -> None:
        outcome = str(data.get("outcome", ""))
        if outcome == "success":
            self.breaches += 1
        elif outcome == "refused":
            self.refused += 1

    def _on_finding_critical(self, data: dict) -> None:
        self.findings += 1
        sev = str(data.get("severity", "critical"))
        title = str(data.get("title", ""))
        self._finding_rows.append((sev, title))
        line = Text("  ⚠ finding  ", style=_SEV_STYLE.get(sev, "crit"))
        line.append(_clip(title, 52), style="text")
        line.append(f"   {sev}", style=_SEV_STYLE.get(sev, "crit"))
        self._milestone(line)

    def _on_report_ready(self, data: dict) -> None:
        self._advance("report")
        grade = str(data.get("grade", "?"))
        self._status = "done" if grade not in ("n/a", "?") else "faulted"
        line = Text("  done  ", style="dim")
        line.append(f"grade {grade}", style=_GRADE_STYLE.get(grade, "dim"))
        line.append(
            f"  ·  score {data.get('score', '?')}"
            f"  ·  {data.get('findings', 0)} findings"
            f"  ·  {data.get('probes', '?')} probes",
            style="dim",
        )
        self._milestone(line)

    def close(self, *, interrupted: bool = False) -> None:
        """Tear down the live dashboard and restore the terminal.

        On a normal finish, transient ``Live.stop()`` clears the dashboard in place so
        the report card can replace it. On interrupt, also hard-reset the terminal:
        Ctrl-C can land mid-ANSI sequence and leave the cursor hidden or the live
        region half-drawn.
        """
        if self._closed:
            return
        self._closed = True
        if self._status == "running":
            self._status = "faulted"
        live = self._live
        self._live = None
        if live is not None:
            try:
                live.stop()  # transient: the dashboard clears, leaving the report card
            except BaseException:  # noqa: BLE001 -- never skip terminal reset on Ctrl-C
                pass
        try:
            self._restore_width()
        except Exception:  # noqa: BLE001
            pass
        if self._tty:
            self._reset_terminal(clear=interrupted)

    def _reset_terminal(self, *, clear: bool) -> None:
        """Show the cursor; optionally wipe the screen after a torn Live teardown.

        Writes raw ANSI to the console file so this still works when Ctrl-C lands
        mid-flush (rich's buffered ``control()`` path can miss the reset).
        """
        try:
            parts = []
            if clear:
                parts.append("\033[H\033[2J")  # cursor home + erase screen
            parts.append("\033[0m")  # reset SGR attributes
            parts.append("\033[?25h")  # show cursor
            self.console.file.write("".join(parts))
            flush = getattr(self.console.file, "flush", None)
            if callable(flush):
                flush()
        except Exception:  # noqa: BLE001 -- best-effort terminal repair
            pass


# --- report card -------------------------------------------------------------
def _grade_badge(grade: str) -> Text:
    style = _GRADE_STYLE.get(grade, "dim")
    return Text(f" {grade} ", style=f"reverse bold {style}")


def _severity_line(sev: dict) -> Text:
    line = Text("   ")
    for key, label in (
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
    ):
        count = int(sev.get(key, 0) or 0)
        style = _SEV_STYLE[key]
        line.append(f"{label} ", style=style if count else "dim")
        if count:
            line.append("█" * min(count, 12), style=style)
            line.append(f" {count}", style="text")
        else:
            line.append("· 0", style="dim")
        line.append("     ")
    return line


def _print_report(r: dict, console: Console, *, console_url: str | None = None) -> None:
    """Render the graded campaign report as a branded card."""
    grade = str(r.get("grade", "?"))
    findings = r.get("findings") or []
    findings_count = r.get("findings_count", len(findings))
    sev = r.get("severity_counts") or {}

    # header
    head = Text("  ")
    head.append(_MARK, style="brand")
    head.append(" respan ", style="text")
    head.append("redteam report", style="dim")
    console.print()
    console.print(head)
    console.print()

    # grade hero
    hero = Text()
    hero.append(_grade_badge(grade))
    hero.append(f"   {r.get('score', '?')}/100", style="text")
    hero.append(f"      resistance {_pct(r.get('resistance_rate', 0))}", style="dim")
    console.print(
        Padding(
            Panel(
                hero,
                box=ROUNDED,
                border_style=_GRADE_STYLE.get(grade, "faint"),
                padding=(0, 3),
                expand=False,
            ),
            (0, 0, 0, 2),
            expand=False,
        )
    )

    meta = Text("   ")
    meta.append(str(r.get("target_label", "?")), style="text")
    meta.append(
        f"  ·  {findings_count} findings"
        f"  ·  {r.get('probes_sent', '?')}/{r.get('probes_total', '?')} probes"
        f"  ·  ${r.get('cost_usd', '?')}"
        f"  ·  {r.get('duration_s', '?')}s",
        style="dim",
    )
    console.print(meta)

    # severity spread
    console.print()
    console.print(_section("severity"))
    console.print(_severity_line(sev))

    # OWASP coverage spine
    tiles = sorted(r.get("category_tiles") or [], key=lambda t: t["category"])
    if tiles:
        console.print()
        console.print(_section("coverage"))
        for t in tiles:
            row = Text("   ")
            row.append(f"{t['category']:<7}", style="brand")
            row.append(f"{_clip(str(t.get('name', '')), 34):<35}", style="text")
            if t.get("gateway_only"):
                row.append("gateway-only", style="brand")
            else:
                g = str(t.get("sub_grade", "?"))
                row.append(f"{g:<4}", style=_GRADE_STYLE.get(g, "dim"))
                row.append(
                    f"{t.get('findings', 0)} · {t.get('probes_used', 0)}p",
                    style="dim",
                )
            console.print(row)

    # findings detail
    console.print()
    console.print(_section("findings"))
    if not findings:
        console.print(Text("   none — the target held", style="good"))
    for f in findings:
        fsev = str(f.get("severity", "?"))
        console.print(_finding_title(fsev, f.get("title", "")))
        tags = [str(f.get("category", ""))]
        if f.get("technique"):
            tags.append(str(f["technique"]))
        if f.get("owasp"):
            tags.append(f"OWASP {f['owasp']}")
        if f.get("atlas"):
            tags.append(f"ATLAS {f['atlas']}")
        console.print(
            Text("             " + " · ".join(t for t in tags if t), style="dim")
        )
        evidence = _clip(f.get("evidence_span") or "", 96)
        if evidence:
            ev = Text("             ", style="dim")
            ev.append(f"“{evidence}”", style="faint")
            console.print(ev)

    # web-console link — last, mirroring the live view's footer
    if console_url:
        console.print()
        console.print(Text("  ").append(console_url, style="dim"), soft_wrap=True)
    console.print()
