import json
from pathlib import Path

import pytest

from alertcheck.adapters.process import ToolFailed, ToolNotFound
from alertcheck.checks.network.ports import PortsCheck, load_ports
from tests.unit.checks.conftest import static_resolver

FIX = Path(__file__).parents[2] / "fixtures" / "tools"


class FakeRunner:
    def __init__(self, output=None, error=None):
        self.output, self.error, self.calls, self.targets = output, error, [], []

    async def __call__(self, argv, *, timeout, ok_codes=(0,)):
        self.calls.append(argv)
        self.targets.append(Path(argv[argv.index("-iL") + 1]).read_text().split())
        if self.error:
            raise self.error
        return self.output


@pytest.fixture
def nmap_xml():
    return (FIX / "nmap.xml").read_text()


async def run(make_ctx, runner, targets, resolver=None, **scope):
    ctx = make_ctx(targets=targets, resolver=resolver or static_resolver(), **scope)
    check = PortsCheck(runner=runner)
    plan = check.plan(ctx)
    result = await check.run(ctx)
    await ctx.aclose()
    return ctx, plan, result


def by_port(result):
    return {f.evidence["port"]: f for f in result.findings}


def test_port_list_is_valid():
    ports = load_ports()
    assert {6379, 23, 3389, 2375} <= {p.port for p in ports}
    assert len({p.port for p in ports}) == len(ports)


class TestFindings:
    async def test_exposed_redis_is_high_a1(self, make_ctx, nmap_xml):
        _, _, result = await run(make_ctx, FakeRunner(nmap_xml), {"domains": ["www.example.co.jp"]})
        redis = by_port(result)[6379]
        assert redis.severity.value == "high"
        assert "A-1" in redis.ipa_items
        assert redis.target == "www.example.co.jp:6379"
        assert redis.evidence["product"] == "Redis key-value store"

    async def test_telnet_high_ssh_medium_web_none(self, make_ctx, nmap_xml):
        _, _, result = await run(make_ctx, FakeRunner(nmap_xml), {"domains": ["www.example.co.jp"]})
        ports = by_port(result)
        assert ports[23].severity.value == "high"
        assert ports[22].severity.value == "medium"
        assert 80 not in ports and 443 not in ports
        assert 3306 not in ports  # filtered, not open

    async def test_open_ports_are_shared_as_artifact(self, make_ctx, nmap_xml):
        _, _, result = await run(make_ctx, FakeRunner(nmap_xml), {"domains": ["www.example.co.jp"]})
        assert result.artifacts["open_ports"]["www.example.co.jp"] == [22, 23, 80, 443, 6379]

    async def test_service_on_non_standard_port(self, make_ctx):
        xml = (FIX / "nmap.xml").read_text().replace('portid="6379"', 'portid="16379"')
        _, _, result = await run(make_ctx, FakeRunner(xml), {"domains": ["www.example.co.jp"]})
        assert by_port(result)[16379].evidence["label"] == "Redis"


class TestScope:
    async def test_only_validated_addresses_are_passed(self, make_ctx, nmap_xml):
        runner = FakeRunner(nmap_xml)
        resolver = static_resolver({"bad.example.co.jp": ["10.0.0.1"]})
        targets = {"domains": ["example.co.jp", "bad.example.co.jp"], "hosts": ["198.51.100.7"]}
        _, _, result = await run(
            make_ctx, runner, targets, resolver=resolver, exclude=["bad.example.co.jp"]
        )
        assert runner.targets == [["93.184.216.34", "198.51.100.7"]]

    async def test_private_resolution_is_never_passed(self, make_ctx, nmap_xml):
        runner = FakeRunner(nmap_xml)
        resolver = static_resolver({"intra.example.co.jp": ["10.0.0.5"]})
        _, _, result = await run(
            make_ctx, runner, {"domains": ["intra.example.co.jp"]}, resolver=resolver
        )
        assert runner.calls == []
        assert result.coverage[0].status == "error"

    async def test_url_prefix_only_target_is_not_scanned(self, make_ctx, nmap_xml):
        runner = FakeRunner(nmap_xml)
        _, plan, result = await run(make_ctx, runner, {"urls": ["https://www.example.co.jp/app/"]})
        assert runner.calls == []
        assert [c.status for c in plan] == ["skipped_by_option"]

    async def test_excluded_networks_are_passed_as_excludes(self, make_ctx, nmap_xml):
        runner = FakeRunner(nmap_xml)
        await run(make_ctx, runner, {"cidrs": ["203.0.113.0/28"]}, exclude=["203.0.113.5"])
        argv = runner.calls[0]
        assert argv[argv.index("--exclude") + 1] == "203.0.113.5/32"
        assert runner.targets == [["203.0.113.0/28"]]

    async def test_unauthorized_scope_plans_nothing(self, make_ctx, nmap_xml):
        ctx = make_ctx(targets={"hosts": ["198.51.100.7"]}, authorization={"confirmed": False})
        assert all(
            c.status != "executed" for c in PortsCheck(runner=FakeRunner(nmap_xml)).plan(ctx)
        )

    async def test_audit_log(self, make_ctx, nmap_xml):
        ctx, _, _ = await run(make_ctx, FakeRunner(nmap_xml), {"hosts": ["198.51.100.7"]})
        events = [json.loads(line) for line in ctx.request_log.read_text().splitlines()]
        assert next(e for e in events if e["event"] == "nmap")["targets"] == ["198.51.100.7"]


class TestFailures:
    @pytest.mark.parametrize(
        "error", [ToolNotFound("nmap not installed"), ToolFailed("nmap exited 1")]
    )
    async def test_tool_problems_are_errors(self, make_ctx, error):
        _, _, result = await run(make_ctx, FakeRunner(error=error), {"hosts": ["198.51.100.7"]})
        assert [c.status for c in result.coverage] == ["error"]

    async def test_invalid_output_is_an_error(self, make_ctx):
        _, _, result = await run(make_ctx, FakeRunner("garbage"), {"hosts": ["198.51.100.7"]})
        assert result.coverage[0].status == "error"
