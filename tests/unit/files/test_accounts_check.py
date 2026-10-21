import datetime as dt

from alertcheck.checks.files.accounts import AccountsCheck, load_rules
from tests.unit.files.conftest import TODAY


def custom_input():
    return {
        "accounts": [
            {
                "path": "inputs/custom.csv",
                "service": "shop",
                "mapping": "custom",
                "columns": {
                    "id": "login",
                    "email": "mail",
                    "role": "role",
                    "status": "status",
                    "mfa": "mfa",
                    "created_at": "created_at",
                    "last_login_at": "last_login_at",
                },
            }
        ],
        "roster": "inputs/roster.csv",
    }


def run(make_ctx, **kw):
    ctx = make_ctx(
        inputs=custom_input(),
        copy={
            "accounts/custom.csv": "inputs/custom.csv",
            "accounts/roster.csv": "inputs/roster.csv",
        },
        **kw,
    )
    import asyncio

    check = AccountsCheck(today=TODAY)
    result = asyncio.run(check.run(ctx))
    return ctx, result


def kinds(result):
    return {
        (f.evidence["rule"], f.evidence.get("account"), f.severity.value) for f in result.findings
    }


def test_rules_file_is_valid():
    rules = load_rules()
    assert {"retired_employee", "reenabled", "mfa_off"} <= {r.id for r in rules}


def test_retired_admin_is_critical(make_ctx):
    _, result = run(make_ctx)
    assert ("retired_employee", "retired", "critical") in kinds(result)
    f = next(f for f in result.findings if f.evidence["rule"] == "retired_employee")
    assert f.ipa_items == ["P2-3"]


def test_unknown_owner_account(make_ctx):
    # "shared" has no email and no owner → not in roster
    _, result = run(make_ctx)
    assert ("shared_account", "shared", "medium") in kinds(result)


def test_recent_admin(make_ctx):
    _, result = run(make_ctx)
    assert ("recent_admin", "admin", "medium") in kinds(result)


def test_mfa_off(make_ctx):
    _, result = run(make_ctx)
    sev = {
        f.evidence["account"]: f.severity.value
        for f in result.findings
        if f.evidence["rule"] == "mfa_off"
    }
    assert sev["admin"] == "high"  # admin without MFA
    assert sev["bob"] == "medium"  # user without MFA


def test_inactive_account(make_ctx):
    _, result = run(make_ctx)
    inactive = {f.evidence["account"] for f in result.findings if f.evidence["rule"] == "inactive"}
    assert "bob" in inactive  # last login 2026-01-01, > 90 days before 2026-10-21


def test_reenabled_vs_previous_snapshot(make_ctx):
    import asyncio

    from alertcheck.core.models import RunResult

    ctx = make_ctx(
        inputs=custom_input(),
        copy={
            "accounts/custom.csv": "inputs/custom.csv",
            "accounts/roster.csv": "inputs/roster.csv",
        },
        run_id="run-2",
    )
    store = ctx.infra.store
    store.save_run(
        RunResult(id="run-0", started_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC), tool_version="0")
    )
    store.save_account_snapshot(
        "run-0",
        "shop",
        [{"account_id": "admin", "status": "disabled", "role": "admin", "mfa": False}],
    )
    result = asyncio.run(AccountsCheck(today=TODAY).run(ctx))
    assert ("reenabled", "admin", "high") in kinds(result)


def test_snapshot_is_saved_for_next_run(make_ctx):
    ctx, _ = run(make_ctx, run_id="run-x")
    snap = ctx.infra.store.account_snapshot("run-x", "shop")
    ids = {r["account_id"] for r in snap}
    assert {"admin", "alice", "bob", "retired", "shared"} == ids


def test_no_accounts_input_is_skipped(make_ctx):
    import asyncio

    ctx = make_ctx(inputs={})
    plan = AccountsCheck(today=TODAY).plan(ctx)
    assert [c.status for c in plan] == ["skipped_no_input"]
    result = asyncio.run(AccountsCheck(today=TODAY).run(ctx))
    assert result.findings == []


def test_missing_file_is_error(make_ctx):
    import asyncio

    ctx = make_ctx(
        inputs={"accounts": [{"path": "inputs/nope.csv", "service": "x", "mapping": "gws"}]}
    )
    result = asyncio.run(AccountsCheck(today=TODAY).run(ctx))
    assert result.coverage[0].status == "error"


def test_first_run_notes_no_previous_snapshot(make_ctx):
    _, result = run(make_ctx, run_id="first")
    assert any("前回データなし" in c.detail for c in result.coverage)
