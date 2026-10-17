import shutil
from pathlib import Path

import pytest

from alertcheck.adapters.process import ToolFailed, ToolNotFound
from alertcheck.checks.files.deps import DepsCheck
from alertcheck.config.scope import ScopeConfig
from alertcheck.core.context import Context, RunOptions
from alertcheck.infra.factory import build_infra

FIX = Path(__file__).parents[2] / "fixtures"


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = (
            outputs  # key "trivy fs" / "trivy image" / "osv-scanner" -> text or exception
        )
        self.calls = []

    async def __call__(self, argv, *, timeout, ok_codes=(0,)):
        self.calls.append(argv)
        key = " ".join(argv[:2]) if argv[0] == "trivy" else argv[0]
        out = self.outputs.get(key, ToolNotFound(argv[0]))
        if isinstance(out, Exception):
            raise out
        return out


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "ws"
    shutil.copytree(FIX / "repos" / "legacy-php", ws / "inputs" / "repos" / "shop")
    cache = tmp_path / "cache"
    cache.mkdir()
    shutil.copy(FIX / "tools" / "kev.json", cache / "kev.json")
    return ws, cache


def make_ctx(ws, deps, offline=False):
    scope = ScopeConfig.model_validate({"organization": "X", "inputs": {"deps": deps}})
    return Context.create(
        scope=scope, infra=build_infra("local", ws), options=RunOptions(offline=offline)
    )


def fixture(name):
    return (FIX / "tools" / name).read_text(encoding="utf-8")


ALL_TOOLS = {
    "trivy fs": fixture("trivy_fs.json"),
    "osv-scanner": fixture("osv.json"),
    "trivy image": fixture("trivy_image.json"),
}


async def run(ws, cache, deps, runner, offline=False, monkeypatch=None):
    check = DepsCheck(runner=runner, cache=cache)
    ctx = make_ctx(ws, deps, offline=offline)
    plan = check.plan(ctx)
    result = await check.run(ctx)
    return plan, result


def by_key(result):
    return {f.evidence.get("vuln", f.evidence.get("kind")): f for f in result.findings}


class TestPlan:
    def test_no_deps_inputs(self, workspace):
        ws, cache = workspace
        plan = DepsCheck(runner=FakeRunner({}), cache=cache).plan(make_ctx(ws, []))
        assert [c.status for c in plan] == ["skipped_no_input"]

    def test_lists_entries(self, workspace):
        ws, cache = workspace
        deps = [{"path": "inputs/repos/shop"}, {"image": "registry.example/shop:1"}]
        plan = DepsCheck(runner=FakeRunner({}), cache=cache).plan(make_ctx(ws, deps))
        assert [c.target for c in plan] == ["inputs/repos/shop", "image:registry.example/shop:1"]


class TestFindings:
    async def test_kev_cve_is_critical(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        f = by_key(result)["CVE-2021-3129"]
        assert f.severity.value == "critical"
        assert f.evidence["kev"] is True
        assert f.ipa_items == ["P1-4"]
        assert "2.5.2" in f.remediation

    async def test_fixed_cve_is_unpatched(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        f = by_key(result)["CVE-2022-29248"]
        assert f.severity.value == "high"
        assert f.evidence["kind"] == "unpatched"
        assert f.evidence["sources"] == ["osv", "trivy"]

    async def test_unfixed_cve_is_medium_with_mitigation(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        f = by_key(result)["CVE-2099-0001"]
        assert f.severity.value == "medium"
        assert f.evidence["kind"] == "no_fix"
        assert "代替策" in f.remediation

    async def test_low_unfixed_stays_low(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        assert by_key(result)["GHSA-xxxx-osv-only"].severity.value == "low"

    async def test_eol_runtime_from_lockfile(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        eol = [f for f in result.findings if f.evidence.get("kind") == "eol_runtime"]
        php = next(
            f
            for f in eol
            if f.evidence["product"] == "php" and f.evidence["source"] == "composer.lock"
        )
        assert php.severity.value == "high"
        assert php.evidence["cycle"] == "7.4"
        assert {f.evidence["product"] for f in eol} >= {"php", "debian"}

    async def test_image_scan_reports_os_eol_and_kev(self, workspace):
        ws, cache = workspace
        _, result = await run(
            ws, cache, [{"image": "registry.example/shop:1"}], FakeRunner(ALL_TOOLS)
        )
        keys = by_key(result)
        assert keys["CVE-2023-4911"].severity.value == "critical"  # in KEV fixture
        os_eol = [f for f in result.findings if f.evidence.get("kind") == "eol_os"]
        assert os_eol and os_eol[0].evidence["os"] == "debian 10.13"
        assert result.coverage[0].target == "image:registry.example/shop:1"

    async def test_findings_have_distinct_ids(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        ids = [f.id for f in result.findings]
        assert len(ids) == len(set(ids))


class TestToolAvailability:
    async def test_one_tool_is_enough(self, workspace):
        ws, cache = workspace
        runner = FakeRunner({"trivy fs": fixture("trivy_fs.json")})
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], runner)
        assert result.coverage[0].status == "executed"
        assert "osv-scanner not installed" in result.coverage[0].detail

    async def test_no_tools_is_an_error_but_eol_still_reported(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], FakeRunner({}))
        assert result.coverage[0].status == "error"
        assert "not installed" in result.coverage[0].detail
        assert any(f.evidence.get("kind") == "eol_runtime" for f in result.findings)

    async def test_tool_failure_is_reported(self, workspace):
        ws, cache = workspace
        runner = FakeRunner(
            {"trivy fs": ToolFailed("trivy exited 2"), "osv-scanner": fixture("osv.json")}
        )
        _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], runner)
        assert result.coverage[0].status == "executed"
        assert "trivy exited 2" in result.coverage[0].detail

    async def test_missing_path_is_an_error(self, workspace):
        ws, cache = workspace
        _, result = await run(ws, cache, [{"path": "inputs/repos/nope"}], FakeRunner(ALL_TOOLS))
        assert result.coverage[0].status == "error"

    async def test_missing_kev_data_is_noted(self, workspace, tmp_path):
        ws, _ = workspace
        empty = tmp_path / "empty-cache"
        empty.mkdir()
        _, result = await run(ws, empty, [{"path": "inputs/repos/shop"}], FakeRunner(ALL_TOOLS))
        assert "KEV data not available" in result.coverage[0].detail
        assert by_key(result)["CVE-2021-3129"].severity.value == "high"


class TestOffline:
    async def test_offline_flags_and_no_http(self, workspace, monkeypatch):
        import httpx

        def no_network(*args, **kwargs):
            raise AssertionError("network access during offline scan")

        monkeypatch.setattr(httpx.AsyncClient, "send", no_network)
        ws, cache = workspace
        runner = FakeRunner(ALL_TOOLS)
        deps = [{"path": "inputs/repos/shop"}, {"image": "registry.example/shop:1"}]
        await run(ws, cache, deps, runner, offline=True)
        trivy_calls = [c for c in runner.calls if c[0] == "trivy"]
        assert trivy_calls and all("--offline-scan" in c for c in trivy_calls)
        assert all("--offline" in c for c in runner.calls if c[0] == "osv-scanner")

    async def test_paths_passed_to_tools_stay_in_workspace(self, workspace):
        ws, cache = workspace
        runner = FakeRunner(ALL_TOOLS)
        await run(ws, cache, [{"path": "inputs/repos/shop"}], runner)
        for call in runner.calls:
            assert call[-1] == str((ws / "inputs" / "repos" / "shop").resolve())


async def test_osv_targets_keep_subdirectories(workspace):
    ws, cache = workspace
    root = (ws / "inputs" / "repos" / "shop").resolve()
    osv_out = fixture("osv.json").replace(
        "/ws/inputs/repos/shop/composer.lock", f"{root}/apps/api/composer.lock"
    )
    runner = FakeRunner({"osv-scanner": osv_out})
    _, result = await run(ws, cache, [{"path": "inputs/repos/shop"}], runner)
    targets = {
        f.target for f in result.findings if f.evidence.get("kind") in ("unpatched", "no_fix")
    }
    assert targets == {"inputs/repos/shop/apps/api/composer.lock"}
