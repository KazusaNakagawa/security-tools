"""Report rendering: self-contained HTML and schema-versioned JSON (design §10)."""

from __future__ import annotations

import re
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from alertcheck.config.questionnaire import load_questions
from alertcheck.core.models import Finding, RunResult, Severity, ipa_sort_key
from alertcheck.judge.definitions import load_definitions

SCHEMA_VERSION = "1.0"
TOP_PRIORITIES = 5

VERDICT_LABELS = {
    "achieved": "達成",
    "partial": "一部達成",
    "not_achieved": "未達",
    "unverified": "未確認",
    "na": "対象外",
}
STATUS_LABELS = {
    "executed": "実行",
    "skipped_no_input": "入力なし",
    "skipped_by_option": "対象外（オプション・許可）",
    "error": "エラー",
}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?(?::[0-9a-fA-F]{1,4})*(?![\w:])"
)


def _redact_ips(value: Any) -> Any:
    if isinstance(value, str):
        value = _IPV4.sub("[IP]", value)
        return _IPV6.sub(lambda m: "[IP]" if m.group(0).count(":") >= 2 else m.group(0), value)
    if isinstance(value, dict):
        return {k: _redact_ips(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_ips(v) for v in value]
    return value


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    def key(f: Finding) -> tuple[int, tuple[int, str], str, str]:
        first_item = min(f.ipa_items, key=ipa_sort_key)
        return (-f.severity.rank, ipa_sort_key(first_item), f.check_id, f.target)

    return sorted(findings, key=key)


def render_json(run: RunResult, *, redact_ips: bool = False) -> dict[str, Any]:
    defs = load_definitions()
    scope = run.scope or {}
    data = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "id": run.id,
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "tool_version": run.tool_version,
            "options": run.options,
            "organization": scope.get("organization"),
        },
        "scope": run.scope,
        "score": run.score.model_dump(mode="json") if run.score else None,
        "items": [
            {
                **i.model_dump(mode="json"),
                "title": defs.items[i.ipa_item].title,
                "category": defs.items[i.ipa_item].category,
            }
            for i in sorted(run.items, key=lambda i: ipa_sort_key(i.ipa_item))
        ],
        "findings": [f.model_dump(mode="json") for f in _sorted_findings(run.findings)],
        "coverage": [c.model_dump(mode="json") for c in run.coverage],
        "answers": [a.model_dump(mode="json") for a in run.answers],
    }
    return _redact_ips(data) if redact_ips else data


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("alertcheck.report", "templates"),
        autoescape=select_autoescape(["html", "j2"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["pct"] = lambda v: "—" if v is None else f"{v * 100:.0f}%"
    # only plain web links become anchors; anything else (javascript:, data:) stays text
    env.tests["weblink"] = lambda url: (
        isinstance(url, str) and url.startswith(("https://", "http://"))
    )
    return env


def render_html(run: RunResult, *, redact_ips: bool = False) -> str:
    data = render_json(run, redact_ips=redact_ips)
    defs = load_definitions()
    questions = {q.id: q for q in load_questions()}
    findings = data["findings"]
    findings_by_id = {f["id"]: f for f in findings}
    priorities = [f for f in findings if Severity(f["severity"]).rank >= Severity.low.rank][
        :TOP_PRIORITIES
    ]

    categories = []
    for cat, label in defs.categories.items():
        cat_items = [i for i in data["items"] if i["category"] == cat]
        counts = {v: sum(1 for i in cat_items if i["verdict"] == v) for v in VERDICT_LABELS}
        rate = (data["score"] or {}).get("by_category", {}).get(cat)
        categories.append({"id": cat, "label": label, "rate": rate, "counts": counts})

    template = _environment().get_template("report.html.j2")
    return template.render(
        run=data["run"],
        scope=data["scope"] or {},
        score=data["score"],
        items=data["items"],
        findings=findings,
        findings_by_id=findings_by_id,
        coverage=data["coverage"],
        answers=[
            {**a, "text": questions[a["question_id"]].text if a["question_id"] in questions else ""}
            for a in data["answers"]
        ],
        priorities=priorities,
        categories=categories,
        category_labels=defs.categories,
        mismatches=[i for i in data["items"] if i["mismatch"]],
        verdict_labels=VERDICT_LABELS,
        status_labels=STATUS_LABELS,
        redacted=redact_ips,
    )
