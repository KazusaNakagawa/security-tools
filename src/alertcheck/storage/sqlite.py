"""SQLite result store via SQLAlchemy Core (design §9).

Core (not the ORM) keeps the SQL portable so the same schema can move to
PostgreSQL for the AWS deployment (design §14.4).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    delete,
    insert,
    select,
)

from alertcheck.core.models import Answer, Coverage, Finding, ItemResult, RunResult, Score

metadata = MetaData()

runs = Table(
    "runs",
    metadata,
    Column("id", String, primary_key=True),
    Column("started_at", String, nullable=False),
    Column("finished_at", String),
    Column("tool_version", String),
    Column("db_updated_at", String),
    Column("options_json", Text),
    Column("scope_hash", String),
    Column("score_json", Text),
    Column("scope_json", Text),
)
findings = Table(
    "findings",
    metadata,
    Column("run_id", String, primary_key=True),
    Column("id", String, primary_key=True),
    Column("check_id", String, nullable=False),
    Column("severity", String, nullable=False),
    Column("target", Text),
    Column("ipa_items", Text),
    Column("title", Text),
    Column("body_json", Text, nullable=False),
)
coverage = Table(
    "coverage",
    metadata,
    Column("run_id", String, index=True),
    Column("seq", Integer),
    Column("check_id", String),
    Column("target", Text),
    Column("status", String),
    Column("detail", Text),
)
answers = Table(
    "answers",
    metadata,
    Column("run_id", String, index=True),
    Column("question_id", String),
    Column("value", String),
    Column("note", Text),
    Column("evidence_path", Text),
)
items = Table(
    "items",
    metadata,
    Column("run_id", String, index=True),
    Column("ipa_item", String),
    Column("verdict", String),
    Column("rationale", Text),
    Column("missing_json", Text),
    Column("findings_json", Text),
    Column("mismatch", Boolean),
)
account_snapshots = Table(
    "account_snapshots",
    metadata,
    Column("run_id", String, index=True),
    Column("service", String),
    Column("account_id", String),
    Column("status", String),
    Column("role", String),
    Column("mfa", Boolean),
)

_RUN_TABLES = (findings, coverage, answers, items, account_snapshots)


class SqliteResultStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{self.path}")
        metadata.create_all(self._engine)
        self._migrate()

    def _migrate(self) -> None:
        """Add columns introduced after a database was created (create_all never alters)."""
        with self._engine.begin() as con:
            for table in metadata.sorted_tables:
                existing = {r[1] for r in con.exec_driver_sql(f"PRAGMA table_info({table.name})")}
                for column in table.columns:
                    if column.name not in existing:
                        ddl = column.type.compile(dialect=self._engine.dialect)
                        con.exec_driver_sql(
                            f"ALTER TABLE {table.name} ADD COLUMN {column.name} {ddl}"
                        )

    def save_run(self, run: RunResult) -> None:
        with self._engine.begin() as con:
            # replace a run saved earlier with the same id (e.g. judged again)
            con.execute(delete(runs).where(runs.c.id == run.id))
            for table in _RUN_TABLES[:-1]:
                con.execute(delete(table).where(table.c.run_id == run.id))
            con.execute(
                insert(runs).values(
                    id=run.id,
                    started_at=run.started_at.isoformat(),
                    finished_at=run.finished_at.isoformat() if run.finished_at else None,
                    tool_version=run.tool_version,
                    options_json=json.dumps(run.options, ensure_ascii=False),
                    score_json=run.score.model_dump_json() if run.score else None,
                    scope_json=json.dumps(run.scope, ensure_ascii=False) if run.scope else None,
                )
            )
            if run.findings:
                con.execute(
                    insert(findings),
                    [
                        {
                            "run_id": run.id,
                            "id": f.id,
                            "check_id": f.check_id,
                            "severity": f.severity.value,
                            "target": f.target,
                            "ipa_items": json.dumps(f.ipa_items),
                            "title": f.title,
                            "body_json": f.model_dump_json(),
                        }
                        for f in run.findings
                    ],
                )
            if run.coverage:
                con.execute(
                    insert(coverage),
                    [
                        {"run_id": run.id, "seq": n, **c.model_dump()}
                        for n, c in enumerate(run.coverage)
                    ],
                )
            if run.answers:
                con.execute(
                    insert(answers), [{"run_id": run.id, **a.model_dump()} for a in run.answers]
                )
            if run.items:
                con.execute(
                    insert(items),
                    [
                        {
                            "run_id": run.id,
                            "ipa_item": i.ipa_item,
                            "verdict": i.verdict,
                            "rationale": i.rationale,
                            "missing_json": json.dumps(i.missing_inputs, ensure_ascii=False),
                            "findings_json": json.dumps(i.findings),
                            "mismatch": i.mismatch,
                        }
                        for i in run.items
                    ],
                )

    def get_run(self, run_id: str) -> RunResult | None:
        with self._engine.connect() as con:
            row = con.execute(select(runs).where(runs.c.id == run_id)).mappings().first()
            if row is None:
                return None
            f_rows = con.execute(
                select(findings.c.body_json)
                .where(findings.c.run_id == run_id)
                .order_by(findings.c.id)
            ).all()
            c_rows = (
                con.execute(
                    select(coverage).where(coverage.c.run_id == run_id).order_by(coverage.c.seq)
                )
                .mappings()
                .all()
            )
            a_rows = con.execute(select(answers).where(answers.c.run_id == run_id)).mappings().all()
            i_rows = con.execute(select(items).where(items.c.run_id == run_id)).mappings().all()
        stored = {f.id: f for f in (Finding.model_validate_json(r[0]) for r in f_rows)}
        return RunResult(
            id=row["id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            tool_version=row["tool_version"],
            options=json.loads(row["options_json"] or "{}"),
            findings=list(stored.values()),
            coverage=[
                Coverage(
                    check_id=r["check_id"],
                    target=r["target"],
                    status=r["status"],
                    detail=r["detail"],
                )
                for r in c_rows
            ],
            answers=[
                Answer(
                    question_id=r["question_id"],
                    value=r["value"],
                    note=r["note"] or "",
                    evidence_path=r["evidence_path"],
                )
                for r in a_rows
            ],
            items=[
                ItemResult(
                    ipa_item=r["ipa_item"],
                    verdict=r["verdict"],
                    rationale=r["rationale"] or "",
                    missing_inputs=json.loads(r["missing_json"] or "[]"),
                    findings=json.loads(r["findings_json"] or "[]"),
                    mismatch=bool(r["mismatch"]),
                )
                for r in i_rows
            ],
            score=Score.model_validate_json(row["score_json"]) if row["score_json"] else None,
            scope=json.loads(row["scope_json"]) if row["scope_json"] else None,
        )

    def _run_ids(self) -> list[str]:
        with self._engine.connect() as con:
            return [r[0] for r in con.execute(select(runs.c.id).order_by(runs.c.started_at.desc()))]

    def list_runs(self) -> list[RunResult]:
        return [r for rid in self._run_ids() if (r := self.get_run(rid))]

    def latest_run(self) -> RunResult | None:
        ids = self._run_ids()
        return self.get_run(ids[0]) if ids else None

    def previous_run(self, before: str) -> RunResult | None:
        with self._engine.connect() as con:
            current = con.execute(select(runs.c.started_at).where(runs.c.id == before)).scalar()
            if current is None:
                return None
            prev = con.execute(
                select(runs.c.id)
                .where(runs.c.started_at < current)
                .order_by(runs.c.started_at.desc())
                .limit(1)
            ).scalar()
        return self.get_run(prev) if prev else None

    def save_account_snapshot(self, run_id: str, service: str, rows: list[dict[str, Any]]) -> None:
        with self._engine.begin() as con:
            con.execute(
                delete(account_snapshots).where(
                    (account_snapshots.c.run_id == run_id)
                    & (account_snapshots.c.service == service)
                )
            )
            if rows:
                con.execute(
                    insert(account_snapshots),
                    [{"run_id": run_id, "service": service, **r} for r in rows],
                )

    def account_snapshot(self, run_id: str, service: str) -> list[dict[str, Any]]:
        with self._engine.connect() as con:
            result = (
                con.execute(
                    select(
                        account_snapshots.c.account_id,
                        account_snapshots.c.status,
                        account_snapshots.c.role,
                        account_snapshots.c.mfa,
                    ).where(
                        (account_snapshots.c.run_id == run_id)
                        & (account_snapshots.c.service == service)
                    )
                )
                .mappings()
                .all()
            )
        return [dict(r) for r in result]
