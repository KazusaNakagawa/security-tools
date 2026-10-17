"""IPA item verdicts and score (spec §5.2 / §5.3, design §8.2).

Principle: an item the tool could not look at is "unverified", never
"achieved". A clean automated result can stand without an answer, but a
"done" answer cannot outweigh a high/critical finding.
"""

from __future__ import annotations

from collections.abc import Iterable

from alertcheck.config.questionnaire import Question, load_questions
from alertcheck.core.models import (
    Answer,
    Coverage,
    Finding,
    ItemResult,
    Score,
    Severity,
    Verdict,
    ipa_sort_key,
)
from alertcheck.judge.definitions import Definitions, ItemDefinition, load_definitions

_ANSWER_RANK = {"not_done": 0, "partial": 1, "done": 2}
_VERDICT_POINTS = {"achieved": 1.0, "partial": 0.5}


def judge(
    findings: list[Finding],
    coverage: list[Coverage],
    answers: list[Answer],
    *,
    available_checks: Iterable[str] | None = None,
    questions: list[Question] | None = None,
    definitions: Definitions | None = None,
) -> list[ItemResult]:
    defs = definitions or load_definitions()
    questions = questions or load_questions()
    question_text = {q.id: q.text for q in questions}
    values = {a.question_id: a.value for a in answers if a.value is not None}
    na_items = {
        item
        for q in questions
        if q.kind == "yes_no" and values.get(q.id) == "no"
        for item in q.na_when_no
    }
    executed = {c.check_id for c in coverage if c.status == "executed"}
    errors = {c.check_id: c.detail for c in coverage if c.status == "error"}
    available = set(available_checks) if available_checks is not None else None

    results = []
    for item_id in sorted(defs.items, key=ipa_sort_key):
        item = defs.items[item_id]
        related = [f for f in findings if item_id in f.ipa_items]
        if item_id in na_items:
            results.append(
                ItemResult(
                    ipa_item=item_id,
                    verdict="na",
                    rationale="質問票で外部公開アプリケーションなしと回答",
                )
            )
            continue
        missing = _missing_inputs(item, executed, errors, available, values, question_text, defs)
        results.append(_judge_item(item_id, item, related, executed, values, missing))
    return results


def _missing_inputs(
    item: ItemDefinition,
    executed: set[str],
    errors: dict[str, str],
    available: set[str] | None,
    values: dict[str, str],
    question_text: dict[str, str],
    defs: Definitions,
) -> list[str]:
    missing = []
    for check in item.requires_coverage:
        if check in executed:
            continue
        if check in errors:
            missing.append(f"{check}: 実行エラー（{errors[check]}）")
        elif available is not None and check not in available:
            missing.append(f"{check}: 未実装の検査（質問票の回答で判定）")
        else:
            missing.append(f"{check}: {defs.input_hints.get(check, '入力が不足している')}")
    missing += [
        f"質問票 {qid}: {question_text.get(qid, '')}" for qid in item.questions if qid not in values
    ]
    return missing


def _judge_item(
    item_id: str,
    item: ItemDefinition,
    related: list[Finding],
    executed: set[str],
    values: dict[str, str],
    missing: list[str],
) -> ItemResult:
    finding_ids = [f.id for f in related]
    ran = [c for c in item.requires_coverage if c in executed]
    not_ran = [c for c in item.requires_coverage if c not in executed]
    answered = {q: values[q] for q in item.questions if q in values}
    status_answers = [v for v in answered.values() if v in _ANSWER_RANK]
    unanswered = [q for q in item.questions if q not in values]

    def result(verdict: Verdict, reasons: list[str], mismatch: bool = False) -> ItemResult:
        return ItemResult(
            ipa_item=item_id,
            verdict=verdict,
            findings=finding_ids,
            missing_inputs=missing,
            rationale="。".join(reasons),
            mismatch=mismatch,
        )

    if not ran and not related:
        if not answered:
            return result("unverified", ["判定に必要な検査結果も質問票の回答もない"])
        if not status_answers:  # every answer is "na"
            return result("na", ["質問票で該当なしと回答"])

    worst_rank = max((f.severity.rank for f in related), default=-1)
    worst_answer = min(status_answers, key=lambda v: _ANSWER_RANK[v]) if status_answers else None
    reasons = []
    if related:
        severity = next(s for s in Severity if s.rank == worst_rank)
        reasons.append(f"関連する検出 {len(related)} 件（最大 {severity.value}）")
    elif ran:
        reasons.append(f"検査 {', '.join(ran)} で問題なし")
    if worst_answer:
        reasons.append(f"質問票の回答: {worst_answer}")
    elif unanswered:
        reasons.append("質問未回答")
    if not_ran and (ran or related):
        reasons.append(f"未実行の検査あり（{', '.join(not_ran)}）")

    high = worst_rank >= Severity.high.rank
    if high or worst_answer == "not_done":
        mismatch = high and worst_answer in ("done", "partial")
        if mismatch:
            reasons.append("回答と検査結果が食い違う（実施済みと回答したが high 以上の問題を検出）")
        return result("not_achieved", reasons, mismatch)
    if (
        worst_rank >= Severity.low.rank
        or worst_answer == "partial"
        or (not_ran and (ran or related))
    ):
        return result("partial", reasons)
    return result("achieved", reasons)


def score(items: list[ItemResult], findings: list[Finding]) -> Score:
    defs = load_definitions()
    counts = {v: 0 for v in ("achieved", "partial", "not_achieved", "unverified", "na")}
    for i in items:
        counts[i.verdict] += 1

    def rate(subset: list[ItemResult]) -> float | None:
        scored = [i for i in subset if i.verdict != "na"]
        if not scored:
            return None
        return sum(_VERDICT_POINTS.get(i.verdict, 0.0) for i in scored) / len(scored)

    by_category = {
        cat: rate([i for i in items if defs.items[i.ipa_item].category == cat])
        for cat in defs.categories
    }
    return Score(
        overall=rate(items),
        by_category=by_category,
        counts=counts,
        critical=sum(1 for f in findings if f.severity == Severity.critical),
        high=sum(1 for f in findings if f.severity == Severity.high),
    )
