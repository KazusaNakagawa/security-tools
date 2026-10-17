"""Questionnaire definitions and answer files (spec §6.5, design Appendix A)."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from alertcheck.config.scope import ConfigError, read_yaml_mapping
from alertcheck.core.models import IPA_ITEMS, Answer

STATUS_VALUES = ("done", "partial", "not_done", "na")
YES_NO_VALUES = ("yes", "no")


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["status", "yes_no"] = "status"
    ipa_items: list[str] = Field(min_length=1)
    text: str
    na_when_no: list[str] = Field(default_factory=list)

    @field_validator("ipa_items", "na_when_no")
    @classmethod
    def _known_items(cls, items: list[str]) -> list[str]:
        unknown = set(items) - IPA_ITEMS
        if unknown:
            raise ValueError(f"unknown IPA item(s): {sorted(unknown)}")
        return items

    @property
    def allowed_values(self) -> tuple[str, ...]:
        return YES_NO_VALUES if self.kind == "yes_no" else STATUS_VALUES


def load_questions() -> list[Question]:
    raw = files("alertcheck.questionnaire").joinpath("questions.yaml").read_text(encoding="utf-8")
    return [Question.model_validate(q) for q in yaml.safe_load(raw)["questions"]]


def render_answers_template(questions: list[Question]) -> str:
    lines = [
        "# alertcheck 質問票の回答",
        "# value: done（実施済み） / partial（一部実施） / not_done（未実施） / na（該当なし）",
        "#        yes / no の質問はその旨を記載しています。未回答は null のままにしてください",
        "answers:",
    ]
    for q in questions:
        hint = "（yes / no）" if q.kind == "yes_no" else ""
        lines += [
            f"  # [{', '.join(q.ipa_items)}] {q.text}{hint}",
            f"  {q.id}:",
            "    value: null",
            '    note: ""',
        ]
    return "\n".join(lines) + "\n"


class _AnswerBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str | None = None
    note: str | None = ""
    evidence_path: str | None = None


def load_answers(path: Path, questions: list[Question] | None = None) -> list[Answer]:
    questions = questions or load_questions()
    by_id = {q.id: q for q in questions}
    data = read_yaml_mapping(path)
    raw = data.get("answers")
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: 'answers' must be a mapping of question id to answer")

    errors: list[str] = []
    answers: list[Answer] = []
    for qid, body in raw.items():
        question = by_id.get(qid)
        if question is None:
            errors.append(f"  - {qid}: unknown question id")
            continue
        try:
            parsed = _AnswerBody.model_validate(body or {})
        except ValidationError as e:
            errors.append(f"  - {qid}: {e.errors()[0]['msg']}")
            continue
        if parsed.value is not None and parsed.value not in question.allowed_values:
            allowed = " / ".join(question.allowed_values)
            errors.append(f"  - {qid}: value must be one of {allowed} (got {parsed.value!r})")
            continue
        answers.append(
            Answer(
                question_id=qid,
                value=parsed.value,
                note=parsed.note or "",
                evidence_path=parsed.evidence_path,
            )
        )
    if errors:
        raise ConfigError(f"{path}: invalid answers\n" + "\n".join(errors))
    return answers
