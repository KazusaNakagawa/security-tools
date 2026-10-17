import json

import httpx
import pytest
import respx

from alertcheck.config.scope import ScopeConfig
from alertcheck.core.scope_guard import GuardedHttpClient, ScopeGuard, ScopeViolation


def make_scope(**overrides) -> ScopeConfig:
    data = {
        "organization": "X",
        "authorization": {"confirmed": True, "approver": "a", "confirmed_at": "2026-10-17"},
        "targets": {
            "domains": ["example.co.jp"],
            "urls": ["https://shop.other.example/app/"],
            "hosts": ["198.51.100.7"],
            "cidrs": ["203.0.113.0/28"],
        },
        "exclude": [
            "https://www.example.co.jp/private/",
            "legacy.example.co.jp",
            "203.0.113.5",
        ],
    }
    data.update(overrides)
    return ScopeConfig.model_validate(data)


def static_resolver(table):
    async def resolve(host):
        return table.get(host, ["93.184.216.34"])

    return resolve


class TestUrlDecision:
    @pytest.fixture
    def guard(self):
        return ScopeGuard(make_scope())

    @pytest.mark.parametrize(
        "url",
        [
            "https://example.co.jp/",
            "https://www.example.co.jp/login",
            "https://a.b.example.co.jp/",
            "https://shop.other.example/app/",
            "https://shop.other.example/app/cart?x=1",
            "http://198.51.100.7/",
            "https://203.0.113.1:8443/",
            "https://203.0.113.15/",
        ],
    )
    def test_allowed(self, guard, url):
        assert guard.check_url(url).allowed, url

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil-example.co.jp/",
            "https://example.co.jp.evil.test/",
            "https://shop.other.example/",
            "https://shop.other.example/application",
            "https://other.example/app/",
            "https://203.0.113.16/",
            "https://198.51.100.8/",
            "ftp://www.example.co.jp/",
            "not a url",
        ],
    )
    def test_denied_out_of_scope(self, guard, url):
        assert not guard.check_url(url).allowed, url

    @pytest.mark.parametrize(
        "url",
        [
            "https://www.example.co.jp/private/",
            "https://www.example.co.jp/private/x",
            "https://legacy.example.co.jp/",
            "https://sub.legacy.example.co.jp/",
            "https://203.0.113.5/",
        ],
    )
    def test_denied_by_exclude(self, guard, url):
        decision = guard.check_url(url)
        assert not decision.allowed
        assert "excluded" in decision.reason

    def test_url_prefix_target_port_must_match(self, guard):
        assert not guard.check_url("https://shop.other.example:8443/app/").allowed

    def test_default_port_is_equivalent(self, guard):
        assert guard.check_url("https://shop.other.example:443/app/").allowed


class TestHostDecision:
    def test_hosts_for_tools_cover_all_targets_minus_excludes(self):
        guard = ScopeGuard(make_scope())
        assert guard.check_host("example.co.jp").allowed
        assert guard.check_host("shop.other.example").allowed
        assert guard.check_host("203.0.113.2").allowed
        assert not guard.check_host("203.0.113.5").allowed
        assert not guard.check_host("legacy.example.co.jp").allowed
        assert not guard.check_host("other.example").allowed

    def test_ipv6_cidr(self):
        guard = ScopeGuard(make_scope(targets={"cidrs": ["2001:db8::/64"]}))
        assert guard.check_host("2001:db8::1").allowed
        assert not guard.check_host("2001:db8:1::1").allowed


class TestAuthorization:
    def test_unconfirmed_denies_everything(self):
        guard = ScopeGuard(make_scope(authorization={"confirmed": False}))
        assert not guard.authorized
        decision = guard.check_url("https://www.example.co.jp/")
        assert not decision.allowed
        assert "authorization" in decision.reason


class TestDnsValidation:
    async def test_private_resolution_is_denied_by_default(self):
        guard = ScopeGuard(
            make_scope(), resolver=static_resolver({"www.example.co.jp": ["10.0.0.5"]})
        )
        decision = await guard.check_resolved("www.example.co.jp")
        assert not decision.allowed
        assert "private" in decision.reason

    @pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "::1", "fd00::1"])
    async def test_internal_ranges_are_denied(self, ip):
        guard = ScopeGuard(make_scope(), resolver=static_resolver({"www.example.co.jp": [ip]}))
        assert not (await guard.check_resolved("www.example.co.jp")).allowed

    async def test_private_resolution_allowed_when_opted_in(self):
        scope = make_scope(limits={"allow_private_targets": True})
        guard = ScopeGuard(scope, resolver=static_resolver({"www.example.co.jp": ["10.0.0.5"]}))
        assert (await guard.check_resolved("www.example.co.jp")).allowed

    async def test_public_ip_outside_cidrs_is_allowed_with_warning(self):
        guard = ScopeGuard(
            make_scope(), resolver=static_resolver({"www.example.co.jp": ["93.184.216.34"]})
        )
        decision = await guard.check_resolved("www.example.co.jp")
        assert decision.allowed
        assert decision.warnings

    async def test_public_ip_inside_cidrs_has_no_warning(self):
        guard = ScopeGuard(
            make_scope(), resolver=static_resolver({"www.example.co.jp": ["203.0.113.3"]})
        )
        decision = await guard.check_resolved("www.example.co.jp")
        assert decision.allowed and not decision.warnings

    async def test_explicit_ip_target_skips_dns_check(self):
        scope = make_scope(targets={"hosts": ["10.1.2.3"]})
        guard = ScopeGuard(scope, resolver=static_resolver({}))
        assert (await guard.check_resolved("10.1.2.3")).allowed

    async def test_unresolvable_host_is_denied(self):
        async def resolve(host):
            return []

        guard = ScopeGuard(make_scope(), resolver=resolve)
        decision = await guard.check_resolved("www.example.co.jp")
        assert not decision.allowed
        assert "resolve" in decision.reason


class TestTargetsForTools:
    async def test_lists_hosts_in_scope(self):
        guard = ScopeGuard(make_scope(), resolver=static_resolver({}))
        hosts = await guard.resolve_targets()
        assert "example.co.jp" in hosts
        assert "shop.other.example" in hosts
        assert "198.51.100.7" in hosts
        assert "203.0.113.0/28" in hosts

    async def test_drops_hosts_that_fail_dns_validation(self):
        guard = ScopeGuard(make_scope(), resolver=static_resolver({"example.co.jp": ["10.0.0.1"]}))
        assert "example.co.jp" not in await guard.resolve_targets()

    async def test_unauthorized_returns_nothing(self):
        guard = ScopeGuard(
            make_scope(authorization={"confirmed": False}), resolver=static_resolver({})
        )
        assert await guard.resolve_targets() == []


def public_resolver():
    return static_resolver({})


class TestGuardedHttpClient:
    @respx.mock
    async def test_in_scope_request_is_sent_and_logged(self, tmp_path):
        respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200, text="ok"))
        log = tmp_path / "requests.jsonl"
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=log, rps=100, concurrency=4) as client:
            resp = await client.get("https://www.example.co.jp/")
        assert resp.status_code == 200
        entry = json.loads(log.read_text().splitlines()[0])
        assert entry["url"] == "https://www.example.co.jp/"
        assert entry["status"] == 200
        assert entry["method"] == "GET"

    @respx.mock
    async def test_out_of_scope_request_raises_and_is_not_sent(self, tmp_path):
        route = respx.get("https://evil.test/").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=tmp_path / "r.jsonl") as client:
            with pytest.raises(ScopeViolation):
                await client.get("https://evil.test/")
        assert not route.called
        assert json.loads((tmp_path / "r.jsonl").read_text())["blocked"] is True

    @respx.mock
    async def test_redirect_within_scope_is_followed(self, tmp_path):
        respx.get("http://www.example.co.jp/").mock(
            return_value=httpx.Response(301, headers={"Location": "https://www.example.co.jp/"})
        )
        respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=tmp_path / "r.jsonl") as client:
            resp = await client.get("http://www.example.co.jp/")
        assert resp.status_code == 200
        assert [str(r.url) for r in resp.history] == ["http://www.example.co.jp/"]

    @respx.mock
    async def test_redirect_out_of_scope_stops_and_reports(self, tmp_path):
        respx.get("https://www.example.co.jp/sso").mock(
            return_value=httpx.Response(302, headers={"Location": "https://idp.vendor.test/login"})
        )
        idp = respx.get("https://idp.vendor.test/login").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=tmp_path / "r.jsonl") as client:
            resp = await client.get("https://www.example.co.jp/sso")
        assert resp.status_code == 302
        assert not idp.called
        assert resp.extensions["alertcheck_blocked_redirect"] == "https://idp.vendor.test/login"

    @respx.mock
    async def test_redirect_loop_is_bounded(self, tmp_path):
        respx.get("https://www.example.co.jp/a").mock(
            return_value=httpx.Response(302, headers={"Location": "/a"})
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=tmp_path / "r.jsonl", max_redirects=3) as c:
            with pytest.raises(httpx.TooManyRedirects):
                await c.get("https://www.example.co.jp/a")

    @respx.mock
    async def test_private_dns_resolution_blocks_request(self, tmp_path):
        route = respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(
            make_scope(), resolver=static_resolver({"www.example.co.jp": ["10.0.0.9"]})
        )
        async with GuardedHttpClient(guard, request_log=tmp_path / "r.jsonl") as client:
            with pytest.raises(ScopeViolation, match="private"):
                await client.get("https://www.example.co.jp/")
        assert not route.called
