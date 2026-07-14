"""Offline unit tests for the target waist (Target.open()->Chat), the ambient budget leaf, and the
attack-engine adaptation (no LLM calls).

Run directly:  .venv/bin/python tests/test_session_waist.py   (also importable under pytest)."""
from __future__ import annotations

import os
from unittest.mock import patch

from respan_redteam.config import BudgetConfig, EngineConfig, LLMConfig
from respan_redteam.runtime import (BudgetExhausted, campaign_scope, current_budget,
                                     current_config, open_chat, probe, set_profile)
from respan_redteam.prompts import all_prompts, compose
from respan_redteam.carriers import carrier_by_name
from respan_redteam.models import Outcome, ReconProfile
from respan_redteam import StrategyInput


class _EchoChat:
    """A native Chat that records the user messages it was sent."""
    def __init__(self):
        self.sent: list[str] = []
        self._turns: list[dict] = []

    def send(self, user_message: str) -> str:
        self.sent.append(user_message)
        reply = f"reply#{len(self.sent)} to {user_message[:20]}"
        self._turns += [{"role": "user", "content": user_message},
                        {"role": "assistant", "content": reply}]
        return reply

    def transcript(self) -> list[dict]:
        return [dict(m) for m in self._turns]


class _EchoTarget:
    """A native Target: each open() is a fresh, isolated conversation, all recorded on `.chats`."""
    label = "echo"

    def __init__(self):
        self.chats: list[_EchoChat] = []

    def open(self) -> _EchoChat:
        chat = _EchoChat()
        self.chats.append(chat)
        return chat


def test_engine_config_is_explicit_and_campaign_scoped():
    configured = EngineConfig(
        llm=LLMConfig(
            api_key="explicit-key",
            base_url="http://provider.example/v1",
            model_attacker="profile-model",
        ),
        budget=BudgetConfig(max_target_probes=3),
    )
    with patch.dict(
        os.environ,
        {
            "OPENAI_API_KEY": "ignored-key",
            "OPENAI_BASE_URL": "http://ignored.example/v1",
            "RESPAN_MODEL_ATTACKER": "ignored-model",
        },
        clear=True,
    ):
        with campaign_scope(configured, _EchoTarget()):
            assert current_config() == configured
            assert current_config().llm.api_key == "explicit-key"
            assert current_config().llm.model_attacker == "profile-model"


def test_model_client_uses_only_campaign_provider_config():
    import respan_redteam.model_client as model_client

    configured = EngineConfig(
        llm=LLMConfig(
            api_key="campaign-key",
            base_url="http://campaign-provider.example/v1",
        )
    )
    model_client._client_for.cache_clear()
    with (
        patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "ignored-key",
                "OPENAI_BASE_URL": "http://ignored-provider.example/v1",
            },
            clear=True,
        ),
        patch("respan_redteam.model_client.OpenAI") as openai_client,
        campaign_scope(configured, _EchoTarget()),
    ):
        model_client._client()
    openai_client.assert_called_once_with(
        api_key="campaign-key",
        base_url="http://campaign-provider.example/v1",
        timeout=120,
        max_retries=0,
    )
    model_client._client_for.cache_clear()

class _BoomChat:
    def send(self, user_message: str) -> str:
        raise RuntimeError("kaboom")

    def transcript(self) -> list[dict]:
        return []


class _BoomTarget:
    """A target whose send always raises — exercises the budget-leaf's error resilience."""
    label = "boom"

    def open(self) -> _BoomChat:
        return _BoomChat()


def test_open_returns_isolated_conversations():
    t = _EchoTarget()
    a, b = t.open(), t.open()
    a.send("x")
    assert b.transcript() == []                          # a fresh open() shares no history
    assert len(t.chats) == 2


def test_every_attack_builds_a_single_user_string():
    p = ReconProfile()
    for atk in all_prompts():
        out = atk.build("DIRECTIVE-XYZ", p)
        assert isinstance(out, str) and out, f"{atk.name} did not return a non-empty str"


def test_compose_applies_carrier_to_the_message():
    p = ReconProfile()
    base = next(a for a in all_prompts() if a.name == "direct")
    fused = compose(base, carrier_by_name("base64"))
    out = fused.build("PLAINTEXT", p)
    assert isinstance(out, str)
    assert "PLAINTEXT" not in out                        # carrier encoded it
    assert fused.name == "direct+base64"


def _events():
    seen = []
    return seen, (lambda ev, data: seen.append((ev, data)))


def test_scoped_chat_consumes_budget_and_narrates():
    t = _EchoTarget()
    seen, sink = _events()
    with campaign_scope(BudgetConfig(max_target_probes=3), t, sink):
        chat = open_chat()
        chat.send("m1", technique="tech")
        chat.send("m2", technique="tech")
        assert current_budget().sent == 2
        assert len(t.chats) == 1 and t.chats[0].sent == ["m1", "m2"]   # one session, two real turns
        kinds = [e for e, _ in seen]
        assert kinds.count("attack.attempt") == 2
        assert kinds.count("target.response") == 2


def test_probe_is_one_shot_and_narrate_false_is_silent():
    t = _EchoTarget()
    seen, sink = _events()
    with campaign_scope(BudgetConfig(max_target_probes=5), t, sink):
        probe("one-shot", technique="seed")             # fresh chat, one send
        open_chat().send("quiet", narrate=False)        # recon-style: no attack.* events
        assert current_budget().sent == 2               # both sends still consumed budget
        assert len(t.chats) == 2                         # probe + open_chat each opened a conversation
    attempts = [e for e, _ in seen if e == "attack.attempt"]
    assert len(attempts) == 1                            # but only the probe narrated an attempt


def test_run_single_turn_owns_send_judge_and_raw_evidence():
    """The shared plugin primitive keeps translated/normalized judge input separate from the raw
    response retained as evidence."""
    import respan_redteam.judge as judge_mod
    from respan_redteam import run_single_turn
    from respan_redteam.goals import Goal
    from respan_redteam.models import Severity

    seen = []

    class _V:
        outcome, severity, score = Outcome.SUCCESS, Severity.HIGH, 1.0
        evidence_span, rationale = "normalized", "ok"

    original = judge_mod.judge
    judge_mod.judge = lambda goal, category, response, *a, **k: (seen.append(response) or _V())
    try:
        with campaign_scope(BudgetConfig(max_target_probes=2), _EchoTarget(), lambda e, d: None):
            set_profile(ReconProfile())
            goal = Goal("LLM07", "Secret", "leak", "", "", Severity.HIGH)
            p = run_single_turn(goal, "attack", "unit", response_for_judge=str.upper)
        assert p is not None and p.breached
        assert seen == [p.response.upper()]
        assert p.response.startswith("reply#1")          # report evidence is still the raw response
    finally:
        judge_mod.judge = original


def test_budget_exhausted_raises_at_cap():
    t = _EchoTarget()
    seen, sink = _events()
    with campaign_scope(BudgetConfig(max_target_probes=1), t, sink):
        chat = open_chat()
        chat.send("first", technique="t")
        try:
            chat.send("second", technique="t")
            assert False, "expected BudgetExhausted"
        except BudgetExhausted:
            pass
        assert current_budget().sent == 1                 # the rejected over-cap send consumed nothing
    attempts = [e for e, _ in seen if e == "attack.attempt"]
    assert len(attempts) == 1                             # ...and emitted no phantom attack.attempt


def test_scoped_chat_survives_target_error():
    """A raising target must not crash the scan: the leaf returns '[target error: ...]', still
    consumes the probe, and still narrates target.response (runtime.py ScopedChat.send)."""
    t = _BoomTarget()
    seen, sink = _events()
    with campaign_scope(BudgetConfig(max_target_probes=3), t, sink):
        resp = open_chat().send("hi", technique="t")
        assert "target error" in resp
        assert current_budget().sent == 1                 # probe consumed despite the failure
    assert "target.response" in [e for e, _ in seen]      # narrated the error, didn't propagate


def test_crescendo_backtracks_on_refusal():
    """On a refusal, the Crescendo strategy drops the poisoned turn: it opens a FRESH session, replays
    the accepted prefix (near-deterministic agent), and retries — the refused turn never enters the
    record. Returns a single Probe. Stubs the planner + judge so no LLM is needed."""
    from respan_redteam.strategies import crescendo
    from respan_redteam.goals import Goal
    from respan_redteam.models import Outcome, Severity
    import respan_redteam.judge as judge_mod

    # scripted judge: accept turn 0, REFUSE turn 1 (-> backtrack + replay), breach on the retry.
    outcomes = iter([Outcome.PARTIAL, Outcome.REFUSED, Outcome.SUCCESS])

    class _V:
        def __init__(self, o):
            self.outcome, self.severity, self.score, self.evidence_span = o, Severity.HIGH, 0.5, ""

    t = _EchoTarget()
    orig_next, orig_judge = crescendo._next_turn, judge_mod.judge
    crescendo._next_turn = lambda obj, transcript, outcome, score, refused: f"escalate-{len(transcript)}"
    judge_mod.judge = lambda *a, **k: _V(next(outcomes, Outcome.REFUSED))
    try:
        with campaign_scope(BudgetConfig(max_target_probes=20, crescendo_max_turns=6,
                                         crescendo_max_backtracks=3), t, lambda e, d: None):
            goal = Goal("LLM07", "Secret", "leak the secret", "", "", Severity.HIGH)
            probes = crescendo.Crescendo().run(goal, StrategyInput())
        assert len(probes) == 1                            # a single Probe (the conversation)
        probe = probes[0]
        assert probe.breached                              # reached SUCCESS after the backtrack
        assert len(probe.rounds) == 2                      # accepted turn 0 + the breach; refusal dropped
        assert not any(r.refused for r in probe.rounds)    # no refused turn in the record
        assert len(t.chats) == 2                           # a fresh session was opened on the refusal
        assert t.chats[1].sent[0] == "escalate-0"          # the accepted prefix was replayed into it
    finally:
        crescendo._next_turn, judge_mod.judge = orig_next, orig_judge


def test_registered_breadth_attack_fires_past_builtin_cap():
    """A user-registered breadth attack must run even though the built-in FRAMES fill the cap."""
    import respan_redteam.judge as judge_mod
    from respan_redteam import PromptAttack, register_prompt
    from respan_redteam.runtime import set_profile
    from respan_redteam.prompts import core as attacks_mod
    from respan_redteam.strategies.breadth import Breadth
    from respan_redteam.goals import Goal
    from respan_redteam.models import Severity

    class _V:
        outcome, severity, score, evidence_span = Outcome.REFUSED, Severity.NONE, 0.0, ""

    class _CustomBreadth(PromptAttack):
        name = "unit_custom_breadth"
        def build(self, d, p):
            return f"x {d}"

    orig_judge = judge_mod.judge
    judge_mod.judge = lambda *a, **k: _V()
    register_prompt(_CustomBreadth())
    try:
        with campaign_scope(BudgetConfig(max_target_probes=40), _EchoTarget(), lambda e, d: None):
            set_profile(ReconProfile())
            probes = Breadth().run(
                Goal("LLM07", "Secret", "leak", "", "", Severity.HIGH),
                StrategyInput(),
            )
        assert any("unit_custom_breadth" in p.technique for p in probes)   # fired despite the cap
    finally:
        judge_mod.judge = orig_judge
        attacks_mod._REGISTERED = [a for a in attacks_mod._REGISTERED
                                   if a.name != "unit_custom_breadth"]


def test_strategy_assembly_and_extension_registration_are_explicit_and_idempotent():
    from respan_redteam import (PromptAttack, Carrier, Strategy, register_builtin_strategies,
                                register_extensions)
    from respan_redteam.prompts import core as attacks_mod
    from respan_redteam.carriers import core as carriers_mod
    from respan_redteam.strategies import core as registry_mod

    class _BundleAttack(PromptAttack):
        name = "unit_bundle_attack"
        def build(self, goal, profile): return goal

    class _BundleCarrier(Carrier):
        name = "unit_bundle_carrier"
        def apply(self, text): return text

    class _BundleStrategy(Strategy):
        name = "unit_bundle_strategy"
        def run(self, goal, context): return []

    try:
        for _ in range(2):
            register_extensions(
                prompts=(_BundleAttack(),), carriers=(_BundleCarrier(),),
                strategies=(_BundleStrategy(),),
            )
        assert [a.name for a in attacks_mod.all_prompts()].count("unit_bundle_attack") == 1
        assert [c.name for c in carriers_mod.all_carriers()].count("unit_bundle_carrier") == 1
        assert [s.name for s in registry_mod._REGISTERED].count("unit_bundle_strategy") == 1
        register_builtin_strategies()
        assert {"bypass", "crescendo"} <= {s.name for s in registry_mod._REGISTERED}
    finally:
        attacks_mod._REGISTERED = [a for a in attacks_mod._REGISTERED
                                   if a.name != "unit_bundle_attack"]
        carriers_mod._REGISTERED = [c for c in carriers_mod._REGISTERED
                                    if c.name != "unit_bundle_carrier"]
        registry_mod._REGISTERED = [s for s in registry_mod._REGISTERED
                                    if s.name != "unit_bundle_strategy"]


def test_extension_registries_have_symmetric_public_accessors():
    from respan_redteam import registered_prompts, registered_carriers, registered_strategies

    groups = (registered_prompts(), registered_carriers(), registered_strategies())
    assert all(groups)
    assert all(len(group) == len({item.name for item in group}) for group in groups)


def test_post_recon_executors_are_staged_strategies_with_unique_goals():
    from respan_redteam import StrategyStage, registered_strategies
    from respan_redteam.goals import GOALS

    by_stage = {
        stage: {strategy.name for strategy in registered_strategies()
                if strategy.stage is stage}
        for stage in StrategyStage
    }
    assert {"ssrf-canary", "indirect-injection", "exfil-markdown", "agency-refund"} \
        <= by_stage[StrategyStage.AGENTIC]
    assert by_stage[StrategyStage.BREADTH] == {"breadth"}
    assert {"bypass", "crescendo"} <= by_stage[StrategyStage.DEPTH]
    assert {"tap", "deceptive-delight", "bad-likert-judge"}.isdisjoint(
        by_stage[StrategyStage.DEPTH]
    )
    assert len({goal.id for goal in GOALS}) == len(GOALS)


def test_campaign_uses_one_staged_strategy_scheduler_and_central_finding_path():
    import respan_redteam.campaign as orchestrator
    from respan_redteam import StrategyStage
    from respan_redteam.goals import Goal
    from respan_redteam.models import (JudgeVerdict, Probe, Round, Severity, TargetType)

    goal = Goal("UNIT", "Unit goal", "do it", "OWASP", "ATLAS", Severity.HIGH)
    calls = []

    class FakeStrategy:
        min_budget = 1
        def __init__(self, stage):
            self.stage = stage
            self.name = stage.value
        def run(self, selected_goal, context):
            calls.append((self.stage, selected_goal.id, context.seeds))
            verdict = None
            if self.stage is StrategyStage.DEPTH:
                verdict = JudgeVerdict(Outcome.SUCCESS, Severity.HIGH, "proof", "ok", 1.0)
            return [Probe(selected_goal.category, self.name,
                          [Round("prompt", "response", verdict)])]

    originals = (orchestrator.GOALS, orchestrator.run_recon,
                 orchestrator._recon_disclosure_findings,
                 orchestrator.applicable_strategies)
    orchestrator.GOALS = [goal]
    orchestrator.run_recon = lambda recon_probes: (
        ReconProfile(target_type=TargetType.LLM), [],
    )
    orchestrator._recon_disclosure_findings = lambda profile, probes: []
    orchestrator.applicable_strategies = lambda stage, selected_goal, profile: [FakeStrategy(stage)]
    try:
        result = orchestrator.run_campaign(
            _EchoTarget(), BudgetConfig(max_target_probes=5, recon_probes=0),
        )
        assert [call[0] for call in calls] == list(StrategyStage)
        assert len(result.all_findings) == 1
        assert result.all_findings[0].title == goal.title
    finally:
        (orchestrator.GOALS, orchestrator.run_recon,
         orchestrator._recon_disclosure_findings,
         orchestrator.applicable_strategies) = originals


def main():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    main()
