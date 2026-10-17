import json
import shutil
from pathlib import Path

import pytest

from alertcheck.adapters.process import ToolFailed, ToolNotFound
from alertcheck.checks.network.vuln_templates import VulnTemplatesCheck

FIX = Path(__file__).parents[2] / "fixtures" / "tools"


class FakeRunner:
    def __init__(self, output=None, error=None):
        self.output, self.error, self.calls, self.targets = output, error, [], []

    async def __call__(self, argv, *, timeout, ok_codes=(0,)):
        self.calls.append(argv)
        list_file = argv[argv.index("-list") + 1]
        self.targets.append(Path(list_file).read_text().split())
        if self.error:
            raise self.error
        return self.output


@pytest.fixture
def cache(tmp_path):
    shutil.copy(FIX / "kev.json", tmp_path / "kev.json")
    return tmp_path


async def run(make_ctx, cache, runner, targets=None, resolver=None):
    ctx = make_ctx(targets=targets or {"domains": ["www.example.co.jp"]}, resolver=resolver)
    check = VulnTemplatesCheck(runner=runner, cache=cache)
    plan = check.plan(ctx)
    result = await check.run(ctx)
    await ctx.aclose()
    return ctx, plan, result


def kinds(result):
    return {(f.evidence["template"], f.severity.value) for f in result.findings}


async def test_hits_become_findings(make_ctx, cache):
    runner = FakeRunner((FIX / "nuclei.jsonl").read_text())
    _, _, result = await run(make_ctx, cache, runner)
    assert kinds(result) == {("git-config", "medium"), ("CVE-2021-41773", "critical")}
    by = {f.evidence["template"]: f for f in result.findings}
    assert by["git-config"].ipa_items == ["A-1"]
    assert by["CVE-2021-41773"].ipa_items == ["P1-4"]
    assert by["CVE-2021-41773"].evidence["kev"] is True
    assert by["git-config"].target == "https://www.example.co.jp/.git/config"
    assert result.artifacts["technologies"] == {"https://www.example.co.jp": ["nginx"]}
    assert result.coverage[0].status == "executed"


async def test_only_validated_hosts_are_passed(make_ctx, cache):
    from tests.unit.checks.conftest import static_resolver

    runner = FakeRunner("")
    resolver = static_resolver({"bad.example.co.jp": ["10.0.0.1"]})
    targets = {"domains": ["example.co.jp"], "urls": ["https://bad.example.co.jp/"]}
    _, _, result = await run(make_ctx, cache, runner, targets=targets, resolver=resolver)
    assert runner.targets == [["https://example.co.jp/"]]
    status = {c.target: c.status for c in result.coverage}
    assert status["https://bad.example.co.jp/"] == "error"


async def test_url_prefix_only_targets_are_not_scanned(make_ctx, cache):
    runner = FakeRunner("")
    _, plan, result = await run(
        make_ctx, cache, runner, targets={"urls": ["https://www.example.co.jp/app/"]}
    )
    assert runner.calls == []
    assert [c.status for c in plan] == ["skipped_by_option"]
    assert [c.status for c in result.coverage] == ["skipped_by_option"]


async def test_safe_flags_and_rate_limit(make_ctx, cache):
    runner = FakeRunner("")
    await run(make_ctx, cache, runner)
    argv = runner.calls[0]
    for flag in ("-ni", "-dr", "-omit-raw", "-disable-update-check"):
        assert flag in argv
    assert argv[argv.index("-rl") + 1] == "100"  # fixture limit


async def test_audit_log_records_the_run(make_ctx, cache):
    ctx, _, _ = await run(make_ctx, cache, FakeRunner(""))
    events = [json.loads(line) for line in ctx.request_log.read_text().splitlines()]
    nuclei = next(e for e in events if e["event"] == "nuclei")
    assert nuclei["targets"] == ["https://www.example.co.jp/"]


async def test_missing_nuclei_is_an_error(make_ctx, cache):
    _, _, result = await run(
        make_ctx, cache, FakeRunner(error=ToolNotFound("nuclei not installed"))
    )
    assert [c.status for c in result.coverage] == ["error"]
    assert "not installed" in result.coverage[0].detail


async def test_nuclei_failure_is_an_error(make_ctx, cache):
    _, _, result = await run(make_ctx, cache, FakeRunner(error=ToolFailed("nuclei exited 1: x")))
    assert result.coverage[0].status == "error"


async def test_no_targets(make_ctx, cache):
    runner = FakeRunner("")
    _, plan, _ = await run(
        make_ctx, cache, runner, targets={"urls": ["http://x.invalid/"], "domains": []}
    )
    assert plan[0].status in ("skipped_by_option", "skipped_no_input")


async def test_audit_log_redacts_secrets_in_target_urls(make_ctx, cache):
    targets = {
        "domains": ["www.example.co.jp"],
        "urls": ["https://www.example.co.jp/app/?token=s3cr3t&page=1"],
    }
    ctx, _, _ = await run(make_ctx, cache, FakeRunner(""), targets=targets)
    log = ctx.request_log.read_text()
    assert "s3cr3t" not in log
    event = next(json.loads(line) for line in log.splitlines() if '"nuclei"' in line)
    assert any("page=1" in t for t in event["targets"])
