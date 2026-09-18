"""Campaign checkpoints: enough state to continue a campaign after its process is lost.

A checkpoint is taken at every goal boundary, so a resumed campaign repeats at most the
goals that were in flight. It is plain JSON (`to_dict` / `from_dict`) so a host can
store it anywhere.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .goals import GOALS_BY_ID
from .models import (DetectedTool, Finding, JudgeVerdict, Outcome, Probe, ReconProfile, Round,
                     Severity, TargetErrorResponse, TargetType)
from .runtime import current_budget, current_usage

CHECKPOINT_VERSION = 1


@dataclass
class CampaignCheckpoint:
    profile: ReconProfile
    recon_probes: list[Probe]
    recon_solved_categories: set[str]
    findings_by_cat: dict[str, list[Finding]]
    per_goal: dict[str, list[Probe]]
    solved: set[str]
    stage_index: int                      # stage in progress
    stage_goal_ids: list[str]             # that stage's goals, in the order it runs them
    next_goal_index: int                  # first goal in `stage_goal_ids` not yet finished
    budget_sent: int = 0
    budget_completed: int = 0
    budget_errored: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    version: int = field(default=CHECKPOINT_VERSION)

    def restore_runtime(self) -> None:
        """Put the probe budget and token usage back into the ambient campaign."""
        budget = current_budget()
        budget.sent, budget.completed, budget.errored = (
            self.budget_sent, self.budget_completed, self.budget_errored)
        usage = current_usage()
        usage.input_tokens, usage.output_tokens = self.input_tokens, self.output_tokens

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "profile": self.profile.to_dict(),
            "recon_probes": [_probe_to_dict(p) for p in self.recon_probes],
            "recon_solved_categories": sorted(self.recon_solved_categories),
            "findings_by_cat": {
                category: [_finding_to_dict(f) for f in findings]
                for category, findings in self.findings_by_cat.items()
            },
            "per_goal": {
                goal_id: [_probe_to_dict(p) for p in probes]
                for goal_id, probes in self.per_goal.items()
            },
            "solved": sorted(self.solved),
            "stage_index": self.stage_index,
            "stage_goal_ids": list(self.stage_goal_ids),
            "next_goal_index": self.next_goal_index,
            "budget_sent": self.budget_sent,
            "budget_completed": self.budget_completed,
            "budget_errored": self.budget_errored,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CampaignCheckpoint:
        if data.get("version") != CHECKPOINT_VERSION:
            raise ValueError(f"unsupported checkpoint version {data.get('version')!r}")
        findings_by_cat: dict[str, list[Finding]] = {}
        for category, findings in data["findings_by_cat"].items():
            restored = [f for f in (_finding_from_dict(item) for item in findings) if f is not None]
            if restored:
                findings_by_cat[category] = restored
        return cls(
            profile=_profile_from_dict(data["profile"]),
            recon_probes=[_probe_from_dict(p) for p in data["recon_probes"]],
            recon_solved_categories=set(data["recon_solved_categories"]),
            findings_by_cat=findings_by_cat,
            per_goal={
                goal_id: [_probe_from_dict(p) for p in probes]
                for goal_id, probes in data["per_goal"].items()
            },
            solved=set(data["solved"]),
            stage_index=int(data["stage_index"]),
            stage_goal_ids=list(data["stage_goal_ids"]),
            next_goal_index=int(data["next_goal_index"]),
            budget_sent=int(data["budget_sent"]),
            budget_completed=int(data["budget_completed"]),
            budget_errored=int(data["budget_errored"]),
            input_tokens=int(data["input_tokens"]),
            output_tokens=int(data["output_tokens"]),
        )


CheckpointSink = Callable[[CampaignCheckpoint], None]



def _verdict_to_dict(verdict: JudgeVerdict | None) -> dict | None:
    if verdict is None:
        return None
    return {"outcome": verdict.outcome.value, "severity": verdict.severity.value,
            "evidence_span": verdict.evidence_span, "rationale": verdict.rationale,
            "score": verdict.score}


def _verdict_from_dict(data: dict | None) -> JudgeVerdict | None:
    if data is None:
        return None
    return JudgeVerdict(outcome=Outcome(data["outcome"]), severity=Severity(data["severity"]),
                        evidence_span=data["evidence_span"], rationale=data["rationale"],
                        score=float(data.get("score", 0.0)))


def _round_to_dict(round_: Round) -> dict:
    return {"prompt": round_.prompt, "response": str(round_.response),
            "is_target_error": isinstance(round_.response, TargetErrorResponse),
            "verdict": _verdict_to_dict(round_.verdict), "errored": round_.errored}


def _round_from_dict(data: dict) -> Round:
    response = data["response"]
    if data.get("is_target_error"):
        response = TargetErrorResponse(response)
    return Round(prompt=data["prompt"], response=response,
                 verdict=_verdict_from_dict(data["verdict"]), errored=bool(data["errored"]))


def _probe_to_dict(probe: Probe) -> dict:
    return {"category": probe.category, "technique": probe.technique,
            "rounds": [_round_to_dict(r) for r in probe.rounds],
            "ground_truth_hit": probe.ground_truth_hit}


def _probe_from_dict(data: dict) -> Probe:
    return Probe(category=data["category"], technique=data["technique"],
                 rounds=[_round_from_dict(r) for r in data["rounds"]],
                 ground_truth_hit=data.get("ground_truth_hit"))


def _finding_to_dict(finding: Finding) -> dict:
    return {"goal_id": finding.goal.id, "probe": _probe_to_dict(finding.probe)}


def _finding_from_dict(data: dict) -> Finding | None:
    goal = GOALS_BY_ID.get(data["goal_id"])
    if goal is None:
        return None  # a goal this engine version no longer ships
    return Finding(goal, _probe_from_dict(data["probe"]))


def _profile_from_dict(data: dict) -> ReconProfile:
    return ReconProfile(
        target_type=TargetType(data["target_type"]),
        reconstructed_system_prompt=data.get("reconstructed_system_prompt"),
        extraction_confidence=float(data.get("extraction_confidence", 0.0)),
        detected_tools=[DetectedTool(**tool) for tool in data.get("detected_tools", [])],
        domain=data.get("domain", ""),
        persona=data.get("persona", ""),
        guardrail_strength=data.get("guardrail_strength", "unknown"),
        refusal_signature=data.get("refusal_signature", ""),
        suggested_attack_angles=list(data.get("suggested_attack_angles", [])),
        notes=data.get("notes", ""),
    )
