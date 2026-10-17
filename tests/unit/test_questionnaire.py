import pytest
import yaml

from alertcheck.config.questionnaire import load_answers, load_questions, render_answers_template
from alertcheck.config.scope import ConfigError
from alertcheck.core.models import IPA_ITEMS


class TestQuestions:
    def test_bundled_questions_are_valid(self):
        questions = load_questions()
        assert len(questions) == 25
        assert len({q.id for q in questions}) == 25
        for q in questions:
            assert set(q.ipa_items) <= IPA_ITEMS

    def test_every_ipa_item_except_automation_only_has_a_question(self):
        covered = {i for q in load_questions() for i in q.ipa_items}
        # S-2 is judged from account ledgers / cloud config only
        assert IPA_ITEMS - covered == {"S-2"}


class TestTemplate:
    def test_template_roundtrips_with_all_unanswered(self, tmp_path):
        p = tmp_path / "questionnaire.yaml"
        p.write_text(render_answers_template(load_questions()), encoding="utf-8")
        answers = load_answers(p)
        assert len(answers) == 25
        assert all(a.value is None for a in answers)

    def test_template_includes_question_text_as_comment(self):
        text = render_answers_template(load_questions())
        assert "# [P1-1] 自組織で独自に構築" in text
        assert "yes / no" in text


def write(tmp_path, data):
    p = tmp_path / "questionnaire.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return p


class TestLoadAnswers:
    def test_valid_answers(self, tmp_path):
        p = write(
            tmp_path,
            {
                "answers": {
                    "q_has_public_app": {"value": "yes"},
                    "q_a2_mfa": {"value": "partial", "note": "admins only"},
                }
            },
        )
        by_id = {a.question_id: a for a in load_answers(p)}
        assert by_id["q_has_public_app"].value == "yes"
        assert by_id["q_a2_mfa"].note == "admins only"

    def test_unknown_question_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="q_unknown"):
            load_answers(write(tmp_path, {"answers": {"q_unknown": {"value": "done"}}}))

    def test_status_value_on_yes_no_question_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="q_has_public_app"):
            load_answers(write(tmp_path, {"answers": {"q_has_public_app": {"value": "done"}}}))

    def test_yes_no_value_on_status_question_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="q_a2_mfa"):
            load_answers(write(tmp_path, {"answers": {"q_a2_mfa": {"value": "yes"}}}))

    def test_invalid_value_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="q_a2_mfa"):
            load_answers(write(tmp_path, {"answers": {"q_a2_mfa": {"value": "maybe"}}}))

    def test_empty_file_means_no_answers(self, tmp_path):
        p = tmp_path / "questionnaire.yaml"
        p.write_text("", encoding="utf-8")
        assert load_answers(p) == []

    def test_answers_must_be_mapping(self, tmp_path):
        with pytest.raises(ConfigError, match="answers"):
            load_answers(write(tmp_path, {"answers": ["q_a2_mfa"]}))
