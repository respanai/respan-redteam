"""Checkpoints let a campaign continue after its process is lost.

A campaign resumed from a mid-run checkpoint must end exactly where an uninterrupted
run ends, without repeating finished work.
"""

import json

import pytest

from respan_redteam import model_client
from respan_redteam.campaign import run_campaign
from respan_redteam.checkpoint import CampaignCheckpoint
from respan_redteam.config import BudgetConfig, EngineConfig
from respan_redteam.model_client import LLMResult
from respan_redteam.runtime import Usage

CANARY = "RESPAN-HIJACK-9F3A"
CONFIG = EngineConfig(budget=BudgetConfig(max_target_probes=40, goal_concurrency=1,
                                          recon_concurrency=1))


class _Chat:
    def __init__(self, target):
        self._target = target

    def send(self, message):
        self._target.sends += 1
        return CANARY if CANARY in message else "I cannot help with that."

    def transcript(self):
        return []


class _Target:
    label = "fake"

    def __init__(self):
        self.sends = 0

    def open(self):
        return _Chat(self)


@pytest.fixture(autouse=True)
def _faked_llm(monkeypatch):
    def complete(model_id, user=None, system=None, **kwargs):
        return LLMResult(text="attack prompt", usage=Usage(input_tokens=3, output_tokens=2))

    def complete_json(model_id, user=None, system=None, **kwargs):
        if "candidate attack prompts" in (user or ""):
            return ["a", "b", "c"]
        if "RECON PROBE RESPONSES" in (user or ""):
            return {"target_type": "llm", "guardrail_strength": "low"}
        if "worth grading" in (system or ""):
            return {"verdict": "refused", "reason": "refused"}
        return {"specificity": 1, "actionability": 1, "evidence_span": "",
                "severity": "low", "rationale": "refused"}

    monkeypatch.setattr(model_client, "complete", complete)
    monkeypatch.setattr(model_client, "complete_json", complete_json)
    import respan_redteam.judge as judge_module

    monkeypatch.setattr(judge_module, "model_client", model_client)


def _run(resume_from=None):
    target, checkpoints = _Target(), []
    result = run_campaign(target, config=CONFIG, resume_from=resume_from,
                          on_checkpoint=lambda checkpoint: checkpoints.append(checkpoint.to_dict()))
    return result, target, checkpoints


def _findings(result):
    return sorted((finding.title, finding.technique) for finding in result.all_findings)


def test_every_checkpoint_survives_a_json_round_trip():
    _, _, checkpoints = _run()

    assert len(checkpoints) > 2
    for data in checkpoints:
        restored = CampaignCheckpoint.from_dict(json.loads(json.dumps(data)))
        assert restored.to_dict() == data


def test_resumed_campaign_ends_where_an_uninterrupted_one_does():
    full_result, full_target, checkpoints = _run()
    midway = checkpoints[len(checkpoints) // 2]

    resumed_result, resumed_target, _ = _run(CampaignCheckpoint.from_dict(midway))

    assert _findings(resumed_result) == _findings(full_result)
    assert resumed_result.probes_sent == full_result.probes_sent
    assert resumed_result.grade() == full_result.grade()
    # Recon and every goal before the checkpoint are not run again.
    assert resumed_target.sends == full_target.sends - midway["budget_sent"]


def test_unknown_checkpoint_version_is_refused():
    _, _, checkpoints = _run()

    with pytest.raises(ValueError):
        CampaignCheckpoint.from_dict({**checkpoints[0], "version": 999})
