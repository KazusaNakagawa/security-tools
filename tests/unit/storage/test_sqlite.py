import datetime as dt
import sqlite3

import pytest

from alertcheck.core.models import Answer, Coverage, Finding, ItemResult, RunResult, Score, Severity
from alertcheck.storage.sqlite import SqliteResultStore


def make_run(run_id, day, findings=(), status="active"):
    f = Finding.create(
        check_id="http.headers",
        kind="csp",
        target="https://a.example/",
        ipa_items=["A-6"],
        severity=Severity.medium,
        title="CSP がない",
        description="d",
        remediation="r",
        evidence={"header": "absent"},
        references=["https://owasp.org"],
    )
    return RunResult(
        id=run_id,
        started_at=dt.datetime(2026, 10, day, 9, tzinfo=dt.UTC),
        finished_at=dt.datetime(2026, 10, day, 9, 5, tzinfo=dt.UTC),
        tool_version="0.1.0",
        options={"offline": False, "only": ["http"]},
        findings=list(findings) or [f],
        coverage=[
            Coverage(check_id="http.headers", target="https://a.example/", status="executed")
        ],
        answers=[Answer(question_id="q_a6_extra", value="partial", note="WAF 検討中")],
        items=[
            ItemResult(
                ipa_item="A-6",
                verdict="partial",
                findings=[f.id],
                missing_inputs=["x"],
                rationale="r",
                mismatch=False,
            )
        ],
        score=Score(
            overall=0.5,
            by_category={"app_measure": 0.5, "management": None},
            counts={"partial": 1},
            critical=0,
            high=0,
        ),
    )


@pytest.fixture
def store(tmp_path):
    return SqliteResultStore(tmp_path / "out" / "alertcheck.db")


def test_roundtrip(store):
    run = make_run("r1", 1)
    store.save_run(run)
    assert store.get_run("r1") == run


def test_unknown_run(store):
    assert store.get_run("nope") is None


def test_previous_and_latest(store):
    store.save_run(make_run("r2", 2))
    store.save_run(make_run("r1", 1))
    store.save_run(make_run("r3", 3))
    assert store.previous_run(before="r3").id == "r2"
    assert store.previous_run(before="r1") is None
    assert store.previous_run(before="nope") is None
    assert store.latest_run().id == "r3"
    assert [r.id for r in store.list_runs()] == ["r3", "r2", "r1"]


def test_empty_store(store):
    assert store.latest_run() is None
    assert store.list_runs() == []


def test_saving_twice_replaces(store):
    store.save_run(make_run("r1", 1))
    updated = make_run("r1", 1)
    updated.items[0].verdict = "achieved"
    store.save_run(updated)
    assert store.get_run("r1").items[0].verdict == "achieved"
    assert len(store.list_runs()) == 1


def test_persists_across_instances(tmp_path):
    path = tmp_path / "db.sqlite"
    SqliteResultStore(path).save_run(make_run("r1", 1))
    assert SqliteResultStore(path).get_run("r1").id == "r1"


def test_schema_matches_design(store):
    store.save_run(make_run("r1", 1))
    con = sqlite3.connect(store.path)
    tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    assert {"runs", "findings", "coverage", "answers", "items", "account_snapshots"} <= tables
    row = con.execute("select id, check_id, severity, ipa_items from findings").fetchone()
    assert row[1:] == ("http.headers", "medium", '["A-6"]')


def test_account_snapshots(store):
    store.save_run(make_run("r1", 1))
    rows = [{"account_id": "alice", "status": "active", "role": "admin", "mfa": True}]
    store.save_account_snapshot("r1", "gws", rows)
    assert store.account_snapshot("r1", "gws") == rows
    assert store.account_snapshot("r1", "other") == []


def test_scope_snapshot_roundtrip(store):
    run = make_run("r1", 1)
    run.scope = {"organization": "株式会社サンプル", "targets": {"urls": ["https://a.example/"]}}
    store.save_run(run)
    assert store.get_run("r1").scope == run.scope


def test_old_database_is_migrated(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE runs (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, "
        "tool_version TEXT, db_updated_at TEXT, options_json TEXT, scope_hash TEXT, "
        "score_json TEXT)"
    )
    con.execute(
        "INSERT INTO runs (id, started_at, tool_version) "
        "VALUES ('old', '2026-10-01T00:00:00+00:00', '0.1.0')"
    )
    con.commit()
    con.close()
    store = SqliteResultStore(path)
    assert store.get_run("old").scope is None
    store.save_run(make_run("new", 2))
    assert store.latest_run().id == "new"


def test_latest_account_snapshot(store):
    store.save_run(make_run("r1", 1))
    store.save_run(make_run("r2", 2))
    store.save_account_snapshot(
        "r1", "gws", [{"account_id": "a", "status": "disabled", "role": "user", "mfa": False}]
    )
    store.save_account_snapshot(
        "r2", "gws", [{"account_id": "a", "status": "active", "role": "user", "mfa": True}]
    )
    assert store.latest_account_snapshot("gws") == [
        {"account_id": "a", "status": "active", "role": "user", "mfa": True}
    ]
    # excluding the newest falls back to the earlier run
    assert store.latest_account_snapshot("gws", exclude="r2") == [
        {"account_id": "a", "status": "disabled", "role": "user", "mfa": False}
    ]
    assert store.latest_account_snapshot("other") == []
