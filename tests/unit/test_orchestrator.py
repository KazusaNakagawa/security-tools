import asyncio

from alertcheck.config.scope import ScopeConfig
from alertcheck.core.context import Context, RunOptions
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity
from alertcheck.core.orchestrator import Orchestrator
from alertcheck.core.registry import Registry
from alertcheck.infra.factory import build_infra


def scope(confirmed=True):
    auth = {"confirmed": True, "approver": "a", "confirmed_at": "2026-10-17"} if confirmed else {}
    return ScopeConfig(organization="X", authorization=auth, targets={"domains": ["example.co.jp"]})


def ctx(tmp_path, *, confirmed=True, **opts):
    infra = build_infra("local", tmp_path)
    return Context.create(scope=scope(confirmed), infra=infra, options=RunOptions(**opts))


class Check:
    def __init__(
        self,
        id,
        *,
        group="network",
        requires=(),
        active=False,
        plan_status="executed",
        finding=None,
        fail=False,
        delay=0.0,
        log=None,
    ):
        self.id, self.group, self.requires, self.active = id, group, list(requires), active
        self.ipa_items = ["A-1"]
        self.plan_status, self.finding, self.fail, self.delay, self.log = (
            plan_status,
            finding,
            fail,
            delay,
            log,
        )

    def plan(self, ctx):
        return [Coverage(check_id=self.id, target="*", status=self.plan_status, detail="planned")]

    async def run(self, ctx):
        if self.log is not None:
            self.log.append(("start", self.id))
        await asyncio.sleep(self.delay)
        if self.fail:
            raise RuntimeError("kaboom")
        if self.log is not None:
            self.log.append(("end", self.id))
        findings = [self.finding] if self.finding else []
        return CheckResult(
            findings=findings,
            coverage=[Coverage(check_id=self.id, target="*", status="executed")],
            artifacts={"seen": True},
        )


def statuses(run):
    return {c.check_id: (c.status, c.detail) for c in run.coverage}


def registry(*checks):
    reg = Registry()
    for c in checks:
        reg.register(c)
    return reg


async def test_runs_checks_and_collects_results(tmp_path):
    f = Finding.create(
        check_id="a",
        kind="k",
        target="t",
        ipa_items=["A-1"],
        severity=Severity.high,
        title="t",
        description="d",
        remediation="r",
        evidence={"email": "yamada@example.co.jp"},
    )
    c = ctx(tmp_path)
    run = await Orchestrator(registry(Check("a", finding=f)), c).run()
    assert statuses(run)["a"][0] == "executed"
    assert run.findings[0].evidence == {"email": "y***@example.co.jp"}
    assert c.artifacts["a"] == {"seen": True}
    assert run.finished_at is not None


async def test_network_checks_skipped_without_authorization(tmp_path):
    reg = registry(Check("ports"), Check("logs.access", group="files"))
    run = await Orchestrator(reg, ctx(tmp_path, confirmed=False)).run()
    s = statuses(run)
    assert s["ports"] == ("skipped_by_option", "authorization.confirmed is false")
    assert s["logs.access"][0] == "executed"


async def test_active_checks_need_flag(tmp_path):
    reg = registry(Check("auth.active", active=True))
    assert (
        statuses(await Orchestrator(reg, ctx(tmp_path)).run())["auth.active"][0]
        == "skipped_by_option"
    )
    run = await Orchestrator(reg, ctx(tmp_path, active=True)).run()
    assert statuses(run)["auth.active"][0] == "executed"


async def test_offline_skips_network_checks(tmp_path):
    reg = registry(Check("ports"), Check("deps", group="files"))
    s = statuses(await Orchestrator(reg, ctx(tmp_path, offline=True)).run())
    assert s["ports"] == ("skipped_by_option", "--offline")
    assert s["deps"][0] == "executed"


async def test_only_and_skip_match_id_or_group_prefix(tmp_path):
    reg = registry(Check("http.headers"), Check("http.cookies"), Check("ports"))
    s = statuses(await Orchestrator(reg, ctx(tmp_path, only={"http"}, skip={"http.cookies"})).run())
    assert s["http.headers"][0] == "executed"
    assert s["http.cookies"][0] == "skipped_by_option"
    assert s["ports"][0] == "skipped_by_option"


async def test_no_input_checks_are_not_run(tmp_path):
    log = []
    reg = registry(Check("logs.access", group="files", plan_status="skipped_no_input", log=log))
    s = statuses(await Orchestrator(reg, ctx(tmp_path)).run())
    assert s["logs.access"] == ("skipped_no_input", "planned")
    assert log == []


async def test_failure_is_isolated(tmp_path):
    reg = registry(Check("a", fail=True), Check("b"))
    s = statuses(await Orchestrator(reg, ctx(tmp_path)).run())
    assert s["a"][0] == "error" and "kaboom" in s["a"][1]
    assert s["b"][0] == "executed"


async def test_dependent_is_skipped_when_dependency_did_not_run(tmp_path):
    reg = registry(Check("a", fail=True), Check("b", requires=["a"]))
    s = statuses(await Orchestrator(reg, ctx(tmp_path)).run())
    assert s["b"] == ("skipped_by_option", "dependency a did not run")


async def test_stage_runs_concurrently_and_stages_in_order(tmp_path):
    log = []
    reg = registry(
        Check("a", delay=0.02, log=log),
        Check("b", delay=0.0, log=log),
        Check("c", requires=["a", "b"], log=log),
    )
    await Orchestrator(reg, ctx(tmp_path)).run()
    assert log.index(("start", "b")) < log.index(("end", "a"))
    assert log.index(("start", "c")) > log.index(("end", "a"))


def test_plan_without_running(tmp_path):
    reg = registry(Check("ports"), Check("auth.active", active=True))
    plan = {c.check_id: c.status for c in Orchestrator(reg, ctx(tmp_path)).plan()}
    assert plan == {"ports": "executed", "auth.active": "skipped_by_option"}


class BrokenPlan(Check):
    def plan(self, ctx):
        raise ValueError("bad input")


async def test_plan_failure_is_isolated(tmp_path):
    reg = registry(BrokenPlan("a"), Check("b"))
    s = statuses(await Orchestrator(reg, ctx(tmp_path)).run())
    assert s["a"][0] == "error" and "bad input" in s["a"][1]
    assert s["b"][0] == "executed"
