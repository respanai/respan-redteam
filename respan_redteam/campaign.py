"""Campaign orchestrator: recon followed by agentic, breadth, and depth strategy stages."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

from .execution.agentic import CanaryCollector
from .config import DEFAULT_ENGINE_CONFIG, BudgetConfig, EngineConfig
from .runtime import (Usage, budget_can_send, budget_remaining, campaign_scope,
                      current_budget, current_usage, emit, set_canary, set_profile)
from .events import (RECON_PHASE, CategoryStart, FindingDetected, ReportReady, SessionStart,
                     StrategyError, StrategyStart)
from .judge import judge as judge_response
from .goals import GOALS, Goal
from .recon import run_recon, _maybe_decode_b64
from .report import GATEWAY_ONLY_INFO
from .strategies import (StrategyInput, StrategyStage, applicable_strategies)
from .target import Target
from .models import (CampaignResult, CategoryResult, Finding, Outcome, Probe, Round,
                    ReconProfile, Severity, SEVERITY_RANK, TargetType, EventSink, null_sink)


def _in_scope(goal: Goal, profile: ReconProfile) -> bool:
    if not goal.requires_tools:
        return True
    have = {t.name for t in profile.detected_tools}
    return any(t in have for t in goal.requires_tools)


def _recon_disclosure_findings(profile, recon_probes) -> list[Finding]:
    """Judge the AGGREGATE extraction disclosure (raw + decoded base64) against the
    system-prompt and secret goals. Catches distributed/side-channel leakage that no
    single-probe judge sees (e.g. the prompt exfiltrated via a base64 side-channel)."""
    parts: list[str] = []
    for p in recon_probes:
        if "extract" in p.category:
            parts.append(p.response)
            dec = _maybe_decode_b64(p.response)
            if dec:
                parts.append(dec)
    blob = "\n\n".join(x for x in parts if x)[:6000]
    findings: list[Finding] = []
    if len(blob.strip()) < 40:
        return findings
    for cat, base in (("LLM07", Severity.HIGH), ("LLM02", Severity.CRITICAL)):
        goal = next((g for g in GOALS if g.category == cat), None)
        if not goal:
            continue
        v = judge_response(goal.text, cat, blob, profile)
        if v.outcome == Outcome.SUCCESS:
            sev = v.severity if SEVERITY_RANK.get(v.severity, 0) >= SEVERITY_RANK[base] else base
            v.severity = sev
            probe = Probe(category=cat, technique="recon-extraction",
                          rounds=[Round(prompt="(aggregate recon extraction battery)",
                                        response=blob, verdict=v)])
            finding = Finding(goal, probe)
            findings.append(finding)
            emit(FindingDetected.from_finding(finding, phase=RECON_PHASE))
    return findings


def run_campaign(
    target: Target,
    config: EngineConfig | BudgetConfig = DEFAULT_ENGINE_CONFIG,
    sink: EventSink = null_sink,
) -> CampaignResult:
    label = getattr(target, "label", "target")
    if isinstance(config, BudgetConfig):
        config = EngineConfig(budget=config)
    with campaign_scope(config, target, sink):
        return _run_campaign(label, config.budget)


def _run_campaign(label: str, cfg: BudgetConfig) -> CampaignResult:
    emit(SessionStart(target=label))

    # --- recon --- (budget/usage/events are all ambient now; probes go through open_chat())
    profile, recon_probes = run_recon(recon_probes=cfg.recon_probes)
    set_profile(profile)                              # make recon profile ambient for strategies

    result = CampaignResult(target_label=label, profile=profile)
    result.all_probes.extend(recon_probes)
    per_goal: dict[str, list[Probe]] = {}
    findings_by_cat: dict[str, list[Finding]] = {}

    # --- harvest recon disclosure into findings ---
    # Recon is often our strongest extraction vector; judge the aggregate so distributed/side-channel leakage counts.
    recon_solved_categories: set[str] = set()
    for f in _recon_disclosure_findings(profile, recon_probes):
        findings_by_cat.setdefault(f.category, []).append(f)
        recon_solved_categories.add(f.category)

    def record(goal: Goal, probes: list[Probe], *, phase: str, strategy: str | None) -> bool:
        per_goal.setdefault(goal.id, []).extend(probes)
        solved = False
        for p in probes:
            if p.breached:
                finding = Finding(goal, p)
                findings_by_cat.setdefault(goal.category, []).append(finding)
                emit(FindingDetected.from_finding(finding, phase=phase, strategy=strategy))
                solved = True
        return solved

    def _safe(label: str, run):
        """Run one strategy; a crash in it (e.g. a mid-campaign target.open() failure on a remote
        scan) is logged and skipped rather than aborting the whole campaign and discarding every
        finding collected so far — recon already tolerates the same failure. None means it raised."""
        try:
            return run()
        except Exception as exc:  # noqa: BLE001
            emit(StrategyError(strategy=label, error=str(exc)))
            return None

    scope = [g for g in GOALS if _in_scope(g, profile)]
    solved: set[str] = set()
    # Recon can solve the direct disclosure goals, but not other goals sharing their OWASP category.
    for g in scope:
        if not g.key and g.category in recon_solved_categories:
            solved.add(g.id)

    # Agentic strategies share one campaign-scoped canary collector. The scheduler treats them like
    # every other post-recon strategy; the try/finally only owns the collector's socket lifecycle.
    canary = None
    try:
        if profile.target_type == TargetType.AGENT:
            canary = CanaryCollector()
            set_canary(canary)

        def _advance_goal(
            goal: Goal, stage: StrategyStage, seeds: tuple,
        ) -> tuple[list[Probe], str | None]:
            """Spend one goal's strategies for a stage, stopping at the first breach.

            Returns the probes rather than recording them: the shared per-goal and
            per-category tables are merged by the caller in goal order, so a stage
            running several goals at once needs no locks and still assembles a
            report that does not depend on which goal finished first.
            """
            strategies = applicable_strategies(stage, goal, profile)
            if not strategies:
                return [], None
            emit(CategoryStart(category=goal.category, phase=stage.value, goal=goal.title))
            strategy_context = StrategyInput(seeds=seeds)
            collected: list[Probe] = []
            for strategy in strategies:
                if budget_remaining() < strategy.min_budget:
                    continue
                emit(StrategyStart(category=goal.category, strategy=strategy.name))
                probes = _safe(
                    strategy.name,
                    lambda s=strategy, g=goal, c=strategy_context: s.run(g, c),
                )
                if probes is None:
                    continue
                collected.extend(probes)
                if any(probe.breached for probe in probes):
                    # This goal is solved; later strategies would waste budget, so the breaching
                    # strategy is always the last one run.
                    return collected, strategy.name
            return collected, None

        def _advance_wave(
            wave: list[Goal], stage: StrategyStage,
        ) -> list[tuple[list[Probe], str | None]]:
            """Advance up to `goal_concurrency` goals together, results in wave order.

            Seeds are read here, before dispatch: a goal seeds only from its OWN
            probes in earlier stages, never from another goal, so nothing in a wave
            depends on anything else in it. Workers get a copy of the campaign
            context, which lives in a ContextVar.
            """
            seeds_for = {
                goal.id: tuple(
                    probe.prompt for probe in per_goal.get(goal.id, []) if not probe.breached
                )[:cfg.strategy_seed_limit]
                for goal in wave
            }
            if len(wave) == 1:
                return [_advance_goal(wave[0], stage, seeds_for[wave[0].id])]
            with ThreadPoolExecutor(max_workers=len(wave)) as pool:
                futures = [
                    pool.submit(copy_context().run, _advance_goal, goal, stage, seeds_for[goal.id])
                    for goal in wave
                ]
                return [future.result() for future in futures]

        # Every post-recon target interaction is a staged Strategy with one input and return shape.
        for stage in (StrategyStage.AGENTIC, StrategyStage.BREADTH, StrategyStage.DEPTH):
            goals = sorted(
                (goal for goal in scope if goal.id not in solved),
                key=lambda goal: SEVERITY_RANK[goal.base_severity], reverse=True,
            )
            goals = [g for g in goals if stage is StrategyStage.AGENTIC or not g.agentic_only]
            # Severity order is preserved ACROSS waves, so the worst goals still
            # claim the shared budget first; only goals of comparable severity
            # inside one window compete for it.
            width = max(1, cfg.goal_concurrency)
            for start in range(0, len(goals), width):
                if not budget_can_send():
                    break
                wave = goals[start:start + width]
                for goal, (probes, strategy) in zip(wave, _advance_wave(wave, stage)):
                    if record(goal, probes, phase=stage.value, strategy=strategy):
                        solved.add(goal.id)
    finally:
        if canary:
            canary.close()

    for probes in per_goal.values():
        result.all_probes.extend(probes)

    # --- assemble per-category results + grade ---
    result.categories = _assemble(scope, per_goal, findings_by_cat)
    result.probes_total = cfg.max_target_probes
    result.probes_sent = current_budget().sent
    result.probes_completed = current_budget().completed
    result.probes_errored = current_budget().errored
    result.finished_at = time.time()
    result.cost_usd = _estimate_cost(current_usage())
    emit(ReportReady(grade=result.grade(), score=result.score(),
                     findings=len(result.all_findings), probes=current_budget().sent,
                     status=result.status))
    return result


# categories a black-box scan can only partially reach -> greyed-out upsell.
# report.py owns the descriptions; derive the list from there so the two never drift.
GATEWAY_ONLY = list(GATEWAY_ONLY_INFO)


def _assemble(scope, per_goal, findings_by_cat) -> list[CategoryResult]:
    cats: dict[str, CategoryResult] = {}
    for g in scope:
        cats.setdefault(g.category, CategoryResult(category=g.category))
    for cat, findings in findings_by_cat.items():
        cr = cats.setdefault(cat, CategoryResult(category=cat))
        cr.findings.extend(findings)
    for probes in per_goal.values():
        for p in probes:
            cr = cats.setdefault(p.category, CategoryResult(category=p.category))
            cr.probes_used += len(p.rounds)
            cr.refused += sum(1 for rd in p.rounds if rd.refused)
    out = list(cats.values())
    for cat in GATEWAY_ONLY:
        cr = CategoryResult(category=cat, status="skipped_gateway_only")
        out.append(cr)
    return out


def _estimate_cost(usage: Usage) -> float:
    # crude: assume the mix skews to sonnet-priced calls
    return round(usage.input_tokens / 1e6 * 3.0 + usage.output_tokens / 1e6 * 15.0, 4)
