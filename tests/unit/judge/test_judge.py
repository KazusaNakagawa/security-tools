import json
import os
from pathlib import Path

import pytest

from alertcheck.core.models import Answer, Coverage, Finding, Severity
from alertcheck.judge.judge import judge, score

GOLDEN = Path(__file__).parents[2] / "fixtures" / "golden"
ALL_CHECKS = {
    "http.headers",
    "http.cookies",
    "http.exposure",
    "http.errors",
    "tls",
    "vuln.version",
    "vuln.templates",
    "deps",
}


def finding(item, severity, kind="k", check="http.headers"):
    return Finding.create(
        check_id=check,
        kind=f"{kind}-{item}-{severity}",
        target="https://a.example/",
        ipa_items=[item],
        severity=Severity(severity),
        title="t",
        description="d",
        remediation="r",
    )


def cov(check, status="executed", detail=""):
    return Coverage(check_id=check, target="*", status=status, detail=detail)


def ans(qid, value):
    return Answer(question_id=qid, value=value)


def by_item(items):
    return {i.ipa_item: i for i in items}


class TestVerdicts:
    def test_nothing_provided_is_unverified_with_missing_inputs(self):
        items = by_item(judge([], [], [], available_checks=ALL_CHECKS))
        assert {i.verdict for i in items.values()} == {"unverified"}
        p12 = items["P1-2"]
        assert any(m.startswith("logs.access: 未実装") for m in p12.missing_inputs)  # until #5
        p14 = items["P1-4"]
        assert any("inputs.deps" in m for m in p14.missing_inputs)
        assert any("q_p1_log_reviewed" in m for m in p12.missing_inputs)
        assert any("未実装" in m for m in items["P1-1"].missing_inputs)  # ports / discovery

    def test_public_app_no_marks_a_series_na(self):
        items = by_item(judge([], [], [ans("q_has_public_app", "no")], available_checks=ALL_CHECKS))
        assert {items[f"A-{n}"].verdict for n in range(1, 7)} == {"na"}
        assert items["P1-1"].verdict == "unverified"

    def test_done_answer_with_high_finding_is_a_mismatch(self):
        items = by_item(
            judge(
                [finding("A-6", "high")],
                [cov("http.headers"), cov("http.errors"), cov("tls")],
                [ans("q_a6_extra", "done")],
                available_checks=ALL_CHECKS,
            )
        )
        a6 = items["A-6"]
        assert a6.verdict == "not_achieved"
        assert a6.mismatch is True
        assert "食い違" in a6.rationale

    def test_clean_checks_without_answer_are_achieved_with_note(self):
        items = by_item(
            judge(
                [],
                [cov("http.headers"), cov("http.errors"), cov("tls")],
                [],
                available_checks=ALL_CHECKS,
            )
        )
        assert items["A-6"].verdict == "achieved"
        assert "質問未回答" in items["A-6"].rationale

    def test_medium_or_low_finding_is_partial(self):
        for sev in ("medium", "low"):
            items = by_item(
                judge(
                    [finding("A-6", sev)],
                    [cov("http.headers"), cov("http.errors"), cov("tls")],
                    [],
                    available_checks=ALL_CHECKS,
                )
            )
            assert items["A-6"].verdict == "partial", sev

    def test_info_finding_does_not_lower_verdict(self):
        items = by_item(
            judge(
                [finding("A-6", "info")],
                [cov("http.headers"), cov("http.errors"), cov("tls")],
                [],
                available_checks=ALL_CHECKS,
            )
        )
        assert items["A-6"].verdict == "achieved"

    def test_partially_executed_requirements_are_partial(self):
        items = by_item(judge([], [cov("http.exposure")], [], available_checks=ALL_CHECKS))
        a1 = items["A-1"]  # ports not implemented
        assert a1.verdict == "partial"
        assert any("ports" in m for m in a1.missing_inputs)

    def test_answer_only_items(self):
        answers = [
            ans("q_m1_leadership", "done"),
            ans("q_m2_supply_chain", "partial"),
            ans("q_m3_communication", "not_done"),
        ]
        items = by_item(judge([], [], answers, available_checks=ALL_CHECKS))
        assert (items["M-1"].verdict, items["M-2"].verdict, items["M-3"].verdict) == (
            "achieved",
            "partial",
            "not_achieved",
        )

    def test_worst_answer_wins(self):
        answers = [ans("q_a2_mfa", "done"), ans("q_a2_password", "not_done")]
        items = by_item(judge([], [], answers, available_checks=ALL_CHECKS))
        assert items["A-2"].verdict == "not_achieved"

    def test_na_answer_alone_is_na(self):
        items = by_item(judge([], [], [ans("q_d3_access_log", "na")], available_checks=ALL_CHECKS))
        assert items["D-3"].verdict == "na"

    def test_na_answer_is_overridden_by_findings(self):
        items = by_item(
            judge(
                [finding("D-2", "critical", check="http.exposure")],
                [cov("http.exposure")],
                [ans("q_d2_location", "na")],
                available_checks=ALL_CHECKS,
            )
        )
        assert items["D-2"].verdict == "not_achieved"

    def test_errored_check_is_reported(self):
        items = by_item(
            judge(
                [], [cov("deps", "error", "trivy not installed")], [], available_checks=ALL_CHECKS
            )
        )
        p14 = items["P1-4"]
        assert p14.verdict == "unverified"
        assert any("実行エラー" in m and "trivy not installed" in m for m in p14.missing_inputs)

    def test_skipped_for_missing_input_uses_hint(self):
        items = by_item(
            judge(
                [],
                [cov("deps", "skipped_no_input", "no deps inputs")],
                [],
                available_checks=ALL_CHECKS,
            )
        )
        assert any("inputs.deps" in m for m in items["P1-4"].missing_inputs)

    def test_findings_are_linked(self):
        f = finding("A-6", "medium")
        items = by_item(judge([f], [cov("http.headers")], [], available_checks=ALL_CHECKS))
        assert items["A-6"].findings == [f.id]

    def test_finding_without_coverage_still_counts_as_evidence(self):
        items = by_item(
            judge(
                [finding("A-1", "high", check="vuln.templates")],
                [],
                [],
                available_checks=ALL_CHECKS,
            )
        )
        assert items["A-1"].verdict == "not_achieved"

    def test_items_are_ordered(self):
        order = [i.ipa_item for i in judge([], [], [], available_checks=ALL_CHECKS)]
        assert order[:2] == ["P1-1", "P1-2"] and order[-1] == "M-3"
        assert order.index("A-1") < order.index("S-1") < order.index("D-1") < order.index("M-1")


class TestScore:
    def test_formula(self):
        answers = [
            ans("q_m1_leadership", "done"),
            ans("q_m2_supply_chain", "partial"),
            ans("q_has_public_app", "no"),
        ]
        items = judge([], [], answers, available_checks=ALL_CHECKS)
        s = score(items, [])
        assert s.counts["na"] == 6
        assert s.counts["achieved"] == 1 and s.counts["partial"] == 1
        assert s.overall == pytest.approx(1.5 / 21)
        assert s.by_category["management"] == pytest.approx(1.5 / 3)
        assert s.by_category["app_measure"] is None  # every item n/a

    def test_unverified_counts_in_denominator(self):
        s = score(judge([], [], [], available_checks=ALL_CHECKS), [])
        assert s.overall == 0.0

    def test_severity_counts(self):
        fs = [
            finding("A-6", "critical"),
            finding("A-6", "high"),
            finding("A-1", "high"),
            finding("A-1", "low"),
        ]
        s = score(judge(fs, [], [], available_checks=ALL_CHECKS), fs)
        assert (s.critical, s.high) == (1, 2)


SCENARIOS = {
    "empty": dict(findings=[], coverage=[], answers=[]),
    "no_public_app": dict(
        findings=[], coverage=[], answers=[("q_has_public_app", "no"), ("q_m1_leadership", "done")]
    ),
    "mismatch": dict(
        findings=[("A-6", "high"), ("A-2", "medium")],
        coverage=["http.headers", "http.errors", "tls", "http.cookies"],
        answers=[("q_a6_extra", "done"), ("q_a2_mfa", "done"), ("q_a2_password", "done")],
    ),
    "partial_checks": dict(
        findings=[("P1-4", "low")], coverage=["deps", "http.exposure"], answers=[]
    ),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_golden(name):
    sc = SCENARIOS[name]
    items = judge(
        [finding(i, s) for i, s in sc["findings"]],
        [cov(c) for c in sc["coverage"]],
        [ans(q, v) for q, v in sc["answers"]],
        available_checks=ALL_CHECKS,
    )
    fs = [finding(i, s) for i, s in sc["findings"]]
    actual = {
        "items": [i.model_dump(mode="json") for i in items],
        "score": score(items, fs).model_dump(mode="json"),
    }
    path = GOLDEN / f"judge_{name}.json"
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(json.dumps(actual, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    assert path.exists(), f"missing golden file {path.name}; run with UPDATE_GOLDEN=1 and review it"
    assert actual == json.loads(path.read_text(encoding="utf-8"))
