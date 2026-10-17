"""Core data models shared by checks, the judge and reports (design §6)."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, field_validator

IPA_ITEMS: frozenset[str] = frozenset(
    [f"P1-{i}" for i in range(1, 5)]
    + [f"P2-{i}" for i in range(1, 4)]
    + [f"P3-{i}" for i in range(1, 3)]
    + [f"A-{i}" for i in range(1, 7)]
    + [f"S-{i}" for i in range(1, 6)]
    + [f"D-{i}" for i in range(1, 5)]
    + [f"M-{i}" for i in range(1, 4)]
)


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def _normalize_target(target: str) -> str:
    """Lower-case scheme and host and treat an empty path as "/".

    Path case and a trailing slash on non-root paths are kept, since
    ``/admin`` and ``/admin/`` can be different resources.
    """
    target = target.strip()
    if "://" not in target:
        return target.lower()
    parts = urlsplit(target)
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def make_finding_id(check_id: str, target: str, kind: str) -> str:
    """Stable ID used to match the same finding across runs (design §6)."""
    key = "\x1f".join([check_id, _normalize_target(target), kind])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _validate_ipa_items(items: list[str]) -> list[str]:
    unknown = [i for i in items if i not in IPA_ITEMS]
    if unknown:
        raise ValueError(f"unknown IPA item(s): {', '.join(unknown)}")
    return items


class Finding(BaseModel):
    id: str
    check_id: str
    ipa_items: list[str] = Field(min_length=1)
    severity: Severity
    target: str
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str
    references: list[str] = Field(default_factory=list)

    _check_ipa_items = field_validator("ipa_items")(_validate_ipa_items)

    @classmethod
    def create(cls, *, check_id: str, kind: str, target: str, **fields: Any) -> Finding:
        return cls(
            id=make_finding_id(check_id, target, kind),
            check_id=check_id,
            target=target,
            **fields,
        )


CoverageStatus = Literal["executed", "skipped_no_input", "skipped_by_option", "error"]


class Coverage(BaseModel):
    check_id: str
    target: str
    status: CoverageStatus
    detail: str = ""


AnswerValue = Literal["done", "partial", "not_done", "na", "yes", "no"]


class Answer(BaseModel):
    question_id: str
    value: AnswerValue | None = None
    note: str = ""
    evidence_path: str | None = None


Verdict = Literal["achieved", "partial", "not_achieved", "unverified", "na"]


class ItemResult(BaseModel):
    ipa_item: str
    verdict: Verdict
    findings: list[str] = Field(default_factory=list)
    missing_inputs: list[str] = Field(default_factory=list)
    rationale: str = ""


class CheckResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)


class RunResult(BaseModel):
    id: str
    started_at: datetime
    finished_at: datetime | None = None
    tool_version: str
    options: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    answers: list[Answer] = Field(default_factory=list)
    items: list[ItemResult] = Field(default_factory=list)
