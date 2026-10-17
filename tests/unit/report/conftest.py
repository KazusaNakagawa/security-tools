import datetime as dt

import pytest

from alertcheck.core.models import Answer, Coverage, Finding, RunResult, Severity
from alertcheck.judge.judge import judge, score


def make_finding(
    kind, severity, items, title="t", evidence=None, target="https://www.example.co.jp/"
):
    return Finding.create(
        check_id="http.exposure",
        kind=kind,
        target=target,
        ipa_items=items,
        severity=Severity(severity),
        title=title,
        description="説明",
        remediation="対策",
        evidence=evidence or {},
        references=["https://owasp.org/x"],
    )


@pytest.fixture
def make_run():
    def factory(findings=None, answers=None, coverage=None, run_id="20261017T000000000000Z-abc"):
        findings = findings if findings is not None else [make_finding("csp", "medium", ["A-6"])]
        coverage = (
            coverage
            if coverage is not None
            else [
                Coverage(
                    check_id="http.exposure", target="https://www.example.co.jp/", status="executed"
                ),
                Coverage(
                    check_id="tls", target="*", status="skipped_no_input", detail="no HTTPS targets"
                ),
            ]
        )
        answers = answers or [
            Answer(question_id="q_m1_leadership", value="done", note="取締役会で承認")
        ]
        items = judge(findings, coverage, answers, available_checks={"http.exposure", "tls"})
        return RunResult(
            id=run_id,
            started_at=dt.datetime(2026, 10, 17, 1, 2, tzinfo=dt.UTC),
            finished_at=dt.datetime(2026, 10, 17, 1, 5, tzinfo=dt.UTC),
            tool_version="0.1.0",
            options={"offline": False},
            findings=findings,
            coverage=coverage,
            answers=answers,
            items=items,
            score=score(items, findings),
            scope={
                "organization": "株式会社サンプル",
                "targets": {
                    "urls": ["https://www.example.co.jp/"],
                    "domains": [],
                    "hosts": [],
                    "cidrs": [],
                },
                "exclude": [],
            },
        )

    return factory
