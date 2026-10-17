from alertcheck.config.questionnaire import load_questions
from alertcheck.core.models import IPA_ITEMS
from alertcheck.judge.definitions import load_definitions


def test_every_ipa_item_is_defined_once():
    defs = load_definitions()
    assert set(defs.items) == IPA_ITEMS


def test_questions_exist_and_are_status_questions():
    questions = {q.id: q for q in load_questions()}
    for item in load_definitions().items.values():
        for qid in item.questions:
            assert qid in questions, qid
            assert questions[qid].kind == "status", qid


def test_every_required_check_has_an_input_hint():
    defs = load_definitions()
    for item in defs.items.values():
        for check in item.requires_coverage:
            assert check in defs.input_hints, check


def test_categories_are_known():
    defs = load_definitions()
    assert {i.category for i in defs.items.values()} == set(defs.categories)


def test_every_item_has_some_source():
    for item_id, item in load_definitions().items.items():
        assert item.requires_coverage or item.questions, item_id
