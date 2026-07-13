"""Campaign orchestrator: recon followed by agentic, breadth, and depth strategy stages."""
from __future__ import annotations

import time

from .execution.agentic import CanaryCollector
from .config import BudgetConfig, DEFAULT_BUDGET
from .runtime import (Usage, budget_remaining, campaign_scope,
                      current_budget, current_usage, emit, set_canary, set_profile)
from .events import (CategoryStart, FindingDetected, ReportReady, SessionStart,
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
            findings.append(Finding(goal, probe))
            emit(FindingDetected(title=goal.title, severity=sev.value))
    return findings


def run_campaign(target: Target, cfg: BudgetConfig = DEFAULT_BUDGET,
                 sink: EventSink = null_sink) -> CampaignResult:
    label = getattr(target, "label", "target")
    with campaign_scope(cfg, target, sink):           # the raw session Target is now ambient
        return _run_campaign(label, cfg)


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

    def record(goal: Goal, probes: list[Probe]) -> bool:
        per_goal.setdefault(goal.id, []).extend(probes)
        solved = False
        for p in probes:
            if p.breached:
                findings_by_cat.setdefault(goal.category, []).append(Finding(goal, p))
                emit(FindingDetected(title=goal.title, severity=p.verdict.severity.value))
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

        # Every post-recon target interaction is a staged Strategy with one input and return shape.
        for stage in (StrategyStage.AGENTIC, StrategyStage.BREADTH, StrategyStage.DEPTH):
            goals = sorted(
                (goal for goal in scope if goal.id not in solved),
                key=lambda goal: SEVERITY_RANK[goal.base_severity], reverse=True,
            )
            for goal in goals:
                if goal.agentic_only and stage is not StrategyStage.AGENTIC:
                    continue
                strategies = applicable_strategies(stage, goal, profile)
                if not strategies:
                    continue
                emit(CategoryStart(category=goal.category, phase=stage.value, goal=goal.title))
                seeds = tuple(
                    probe.prompt for probe in per_goal.get(goal.id, []) if not probe.breached
                )[:cfg.strategy_seed_limit]
                strategy_context = StrategyInput(seeds=seeds)
                for strategy in strategies:
                    if budget_remaining() < strategy.min_budget:
                        continue
                    emit(StrategyStart(category=goal.category, strategy=strategy.name))
                    probes = _safe(
                        strategy.name,
                        lambda s=strategy, g=goal, c=strategy_context: s.run(g, c),
                    )
                    if probes is not None and record(goal, probes):
                        solved.add(goal.id)
                        break
    finally:
        if canary:
            canary.close()

    for probes in per_goal.values():
        result.all_probes.extend(probes)

    # --- assemble per-category results + grade ---
    result.categories = _assemble(scope, per_goal, findings_by_cat)
    result.probes_total = cfg.max_target_probes
    result.probes_sent = current_budget().sent
    result.finished_at = time.time()
    result.cost_usd = _estimate_cost(current_usage())
    emit(ReportReady(grade=result.grade(), score=result.score(),
                     findings=len(result.all_findings), probes=current_budget().sent))
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
