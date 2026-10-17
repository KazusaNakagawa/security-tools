from alertcheck.config.questionnaire import load_questions
from alertcheck.config.scope import ScopeConfig
from alertcheck.core.models import IPA_ITEMS, Answer
from alertcheck.core.plan import build_plan
from alertcheck.infra.local import LocalWorkspace

AUTH = {"confirmed": True, "approver": "a", "confirmed_at": "2026-10-17"}


def scope(**kw):
    data = {"organization": "X", "authorization": AUTH, "targets": {"domains": ["example.co.jp"]}}
    data.update(kw)
    return ScopeConfig.model_validate(data)


def plan(tmp_path, sc, answers=(), offline=False):
    return build_plan(
        sc, LocalWorkspace(tmp_path), list(answers), load_questions(), offline=offline
    )


def test_nothing_provided_leaves_every_item_unverified(tmp_path):
    p = plan(tmp_path, scope(authorization={"confirmed": False}))
    assert set(p.unverified_items) == IPA_ITEMS
    assert p.errors == []


def test_network_authorization_covers_network_items(tmp_path):
    p = plan(tmp_path, scope())
    for item in ["P1-1", "P1-4", "A-1", "A-2", "A-4", "A-6", "D-2", "D-4"]:
        assert item not in p.unverified_items
    assert "P1-2" in p.unverified_items


def test_offline_disables_network_source(tmp_path):
    assert "A-1" in plan(tmp_path, scope(), offline=True).unverified_items


def test_access_logs_cover_log_items(tmp_path):
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "access.log").write_text("x")
    sc = scope(inputs={"access_logs": [{"path": "inputs/*.log", "format": "nginx_combined"}]})
    p = plan(tmp_path, sc)
    for item in ["P1-2", "P1-3", "A-5"]:
        assert item not in p.unverified_items
    assert p.errors == []
    assert any(s.kind == "access_logs" and s.available for s in p.sources)


def test_configured_but_missing_input_is_an_error(tmp_path):
    sc = scope(inputs={"roster": "inputs/hr/roster.csv"})
    p = plan(tmp_path, sc)
    assert any("inputs/hr/roster.csv" in e for e in p.errors)


def test_answered_question_covers_its_items(tmp_path):
    answers = [Answer(question_id="q_m1_leadership", value="done")]
    p = plan(tmp_path, scope(authorization={"confirmed": False}), answers)
    assert "M-1" not in p.unverified_items
    assert "M-2" in p.unverified_items


def test_unanswered_question_does_not_cover(tmp_path):
    answers = [Answer(question_id="q_m1_leadership", value=None)]
    assert (
        "M-1" in plan(tmp_path, scope(authorization={"confirmed": False}), answers).unverified_items
    )


def test_missing_input_hints_name_the_items(tmp_path):
    p = plan(tmp_path, scope())
    hint = next(s for s in p.sources if s.kind == "access_logs")
    assert not hint.available
    assert {"P1-2", "P1-3", "A-5"} <= set(hint.ipa_items)
