import json

import httpx
import pytest
import respx

from alertcheck.config.scope import ScopeConfig
from alertcheck.core.scope_guard import GuardedHttpClient, PinnedBackend, ScopeGuard, ScopeViolation


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
        # a URL-prefix target authorizes that path only, never the whole host
        assert not guard.check_host("shop.other.example").allowed
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
        assert "shop.other.example" not in hosts
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
        intent, outcome = (json.loads(line) for line in log.read_text().splitlines())
        assert intent["event"] == "request"
        assert intent["url"] == "https://www.example.co.jp/"
        assert intent["method"] == "GET"
        assert outcome["event"] == "response"
        assert outcome["status"] == 200

    @respx.mock
    async def test_out_of_scope_request_raises_and_is_not_sent(self, tmp_path):
        route = respx.get("https://evil.test/").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=tmp_path / "r.jsonl") as client:
            with pytest.raises(ScopeViolation):
                await client.get("https://evil.test/")
        assert not route.called
        assert json.loads((tmp_path / "r.jsonl").read_text())["event"] == "blocked"

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


class TestPathBoundaries:
    @pytest.fixture
    def guard(self):
        return ScopeGuard(
            make_scope(targets={"urls": ["https://a.example/admin", "https://b.example/app/"]})
        )

    @pytest.mark.parametrize(
        "url",
        [
            "https://a.example/admin",
            "https://a.example/admin/",
            "https://a.example/admin/users",
            "https://b.example/app/",
            "https://b.example/app",
            "https://b.example/app/x/../y",
        ],
    )
    def test_allowed(self, guard, url):
        assert guard.check_url(url).allowed, url

    @pytest.mark.parametrize(
        "url",
        [
            "https://a.example/administrator",
            "https://b.example/application",
            "https://b.example/app/../admin",
            "https://b.example/app/%2e%2e/admin",
            "https://b.example/app/%2E%2E%2Fadmin",
            "https://b.example/app/..%5cadmin",
            "https://b.example//app/../../admin",
        ],
    )
    def test_denied(self, guard, url):
        assert not guard.check_url(url).allowed, url

    def test_exclusion_cannot_be_bypassed_with_dot_segments(self):
        guard = ScopeGuard(make_scope())
        assert not guard.check_url("https://www.example.co.jp/public/../private/x").allowed
        assert not guard.check_url("https://www.example.co.jp/%70rivate/").allowed


class TestExcludedResolution:
    async def test_domain_resolving_to_excluded_ip_is_denied(self):
        scope = make_scope(exclude=["93.184.216.34"])
        guard = ScopeGuard(
            scope, resolver=static_resolver({"www.example.co.jp": ["93.184.216.34"]})
        )
        decision = await guard.check_resolved("www.example.co.jp")
        assert not decision.allowed
        assert "excluded" in decision.reason


class TestPinnedConnection:
    class FakeBackend:
        def __init__(self):
            self.calls = []

        async def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):
            self.calls.append((host, port))
            return "stream"

        async def sleep(self, seconds):
            return None

    async def test_connects_to_validated_address_only(self):
        guard = ScopeGuard(
            make_scope(), resolver=static_resolver({"www.example.co.jp": ["93.184.216.34"]})
        )
        assert (await guard.check_resolved("www.example.co.jp")).allowed
        inner = self.FakeBackend()
        backend = PinnedBackend(guard, inner=inner)
        assert await backend.connect_tcp("www.example.co.jp", 443) == "stream"
        assert inner.calls == [("93.184.216.34", 443)]

    async def test_unvalidated_host_is_refused(self):
        import httpcore

        guard = ScopeGuard(make_scope(), resolver=static_resolver({}))
        inner = self.FakeBackend()
        with pytest.raises(httpcore.ConnectError):
            await PinnedBackend(guard, inner=inner).connect_tcp("www.example.co.jp", 443)
        assert inner.calls == []

    async def test_ip_literal_in_scope_connects_directly(self):
        guard = ScopeGuard(make_scope(), resolver=static_resolver({}))
        inner = self.FakeBackend()
        await PinnedBackend(guard, inner=inner).connect_tcp("198.51.100.7", 80)
        assert inner.calls == [("198.51.100.7", 80)]

    async def test_ip_literal_out_of_scope_is_refused(self):
        import httpcore

        guard = ScopeGuard(make_scope(), resolver=static_resolver({}))
        with pytest.raises(httpcore.ConnectError):
            await PinnedBackend(guard, inner=self.FakeBackend()).connect_tcp("8.8.8.8", 80)


class TestGuardedHttpClientHardening:
    @respx.mock
    async def test_certificate_verification_is_on_by_default(self, tmp_path):
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            assert client.verify is True
        async with GuardedHttpClient(guard, verify=False) as client:
            assert client.verify is False

    async def test_unverified_client_refuses_credentials(self, tmp_path):
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, verify=False) as client:
            with pytest.raises(ValueError, match="credentials"):
                await client.get("https://www.example.co.jp/", headers={"Authorization": "x"})

    async def test_follow_redirects_kwarg_is_rejected(self):
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            with pytest.raises(ValueError, match="follow_redirects"):
                await client.get("https://www.example.co.jp/", follow_redirects=True)

    @respx.mock
    async def test_credentials_dropped_on_cross_origin_redirect(self, tmp_path):
        respx.get("https://www.example.co.jp/go").mock(
            return_value=httpx.Response(302, headers={"Location": "https://api.example.co.jp/x"})
        )
        target = respx.get("https://api.example.co.jp/x").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            await client.get(
                "https://www.example.co.jp/go",
                headers={"Authorization": "Bearer t", "Cookie": "sid=1", "X-Keep": "1"},
            )
        sent = target.calls.last.request.headers
        assert "authorization" not in sent
        assert "cookie" not in sent
        assert sent["x-keep"] == "1"

    @respx.mock
    async def test_credentials_kept_on_same_origin_redirect(self, tmp_path):
        respx.get("https://www.example.co.jp/a").mock(
            return_value=httpx.Response(302, headers={"Location": "/b"})
        )
        target = respx.get("https://www.example.co.jp/b").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            await client.get("https://www.example.co.jp/a", headers={"Authorization": "Bearer t"})
        assert target.calls.last.request.headers["authorization"] == "Bearer t"

    @respx.mock
    @pytest.mark.parametrize(
        "code,expected", [(301, "GET"), (302, "GET"), (303, "GET"), (307, "POST"), (308, "POST")]
    )
    async def test_post_redirect_method(self, tmp_path, code, expected):
        respx.post("https://www.example.co.jp/form").mock(
            return_value=httpx.Response(code, headers={"Location": "/done"})
        )
        done = respx.route(url="https://www.example.co.jp/done").mock(
            return_value=httpx.Response(200)
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            await client.request("POST", "https://www.example.co.jp/form", data={"a": "1"})
        request = done.calls.last.request
        assert request.method == expected
        assert (request.content == b"") == (expected == "GET")

    @respx.mock
    async def test_transport_errors_are_logged_and_reraised(self, tmp_path):
        respx.get("https://www.example.co.jp/").mock(side_effect=httpx.ConnectTimeout("slow"))
        log = tmp_path / "r.jsonl"
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=log) as client:
            with pytest.raises(httpx.ConnectTimeout):
                await client.get("https://www.example.co.jp/")
        events = [json.loads(line) for line in log.read_text().splitlines()]
        assert [e["event"] for e in events] == ["request", "error"]
        assert "ConnectTimeout" in events[1]["error"]

    @respx.mock
    async def test_request_not_sent_when_intent_log_fails(self, tmp_path):
        route = respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200))
        blocker = tmp_path / "file"
        blocker.write_text("")
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=blocker / "r.jsonl") as client:
            with pytest.raises(OSError):
                await client.get("https://www.example.co.jp/")
        assert not route.called

    @respx.mock
    async def test_secrets_are_redacted_from_log(self, tmp_path):
        respx.get(url__startswith="https://www.example.co.jp/cb").mock(
            return_value=httpx.Response(200)
        )
        log = tmp_path / "r.jsonl"
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, request_log=log) as client:
            await client.get("https://user:pw@www.example.co.jp/cb?token=abc&page=2&api_key=k")
        url = json.loads(log.read_text().splitlines()[0])["url"]
        assert "pw" not in url and "user" not in url
        assert "abc" not in url and "=k" not in url
        assert "page=2" in url

    @respx.mock
    async def test_dns_warnings_are_logged(self, tmp_path):
        respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200))
        log = tmp_path / "r.jsonl"
        guard = ScopeGuard(
            make_scope(), resolver=static_resolver({"www.example.co.jp": ["93.184.216.34"]})
        )
        async with GuardedHttpClient(guard, request_log=log) as client:
            await client.get("https://www.example.co.jp/")
        assert json.loads(log.read_text().splitlines()[0])["warnings"]
        assert guard.warnings


async def test_real_connection_uses_pinned_address(tmp_path):
    """End to end: the name never resolves via system DNS, only via the guard."""
    import asyncio

    seen = []

    async def handle(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        seen.append(data)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    scope = make_scope(
        targets={"domains": ["pinned.invalid"]},
        exclude=[],
        limits={"allow_private_targets": True},
    )
    guard = ScopeGuard(scope, resolver=static_resolver({"pinned.invalid": ["127.0.0.1"]}))
    async with server, GuardedHttpClient(guard) as client:
        resp = await client.get(f"http://pinned.invalid:{port}/")
    assert resp.text == "ok"
    assert b"host: pinned.invalid" in seen[0].lower()


class TestMaxBody:
    @respx.mock
    async def test_body_is_truncated_to_max_body(self):
        respx.get("https://www.example.co.jp/big.sql").mock(
            return_value=httpx.Response(200, content=b"x" * 10_000)
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/big.sql", max_body=1024)
        assert len(resp.content) == 1024
        assert resp.extensions["alertcheck_truncated"] is True

    @respx.mock
    async def test_small_body_is_not_marked_truncated(self):
        respx.get("https://www.example.co.jp/s").mock(return_value=httpx.Response(200, text="ok"))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/s", max_body=1024)
        assert resp.text == "ok"
        assert resp.extensions["alertcheck_truncated"] is False

    @respx.mock
    async def test_exact_limit_is_not_truncated(self):
        respx.get("https://www.example.co.jp/e").mock(
            return_value=httpx.Response(200, content=b"y" * 1024)
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/e", max_body=1024)
        assert len(resp.content) == 1024
        assert resp.extensions["alertcheck_truncated"] is False

    @respx.mock
    async def test_redirects_still_followed_with_max_body(self):
        respx.get("https://www.example.co.jp/a").mock(
            return_value=httpx.Response(302, headers={"Location": "/b"})
        )
        respx.get("https://www.example.co.jp/b").mock(return_value=httpx.Response(200, text="b"))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/a", max_body=10)
        assert resp.text == "b"
        assert len(resp.history) == 1

    async def test_non_positive_max_body_is_rejected(self):
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            with pytest.raises(ValueError, match="max_body"):
                await client.get("https://www.example.co.jp/", max_body=0)


class CountingStream(httpx.AsyncByteStream):
    def __init__(self, total, chunk=1024):
        self.total, self.chunk, self.consumed = total, chunk, 0

    async def __aiter__(self):
        while self.consumed < self.total:
            self.consumed += self.chunk
            yield b"z" * self.chunk


class TestBoundedReads:
    @respx.mock
    async def test_stops_reading_at_limit(self):
        stream = CountingStream(10_000_000)
        respx.get("https://www.example.co.jp/huge").mock(
            return_value=httpx.Response(200, stream=stream)
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/huge", max_body=4096)
        assert len(resp.content) == 4096
        assert stream.consumed <= 4096 + 1024

    @respx.mock
    async def test_gzip_bomb_is_bounded(self):
        import gzip

        bomb = gzip.compress(b"0" * 20_000_000)
        respx.get("https://www.example.co.jp/bomb").mock(
            return_value=httpx.Response(200, content=bomb, headers={"Content-Encoding": "gzip"})
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/bomb", max_body=1024)
        assert resp.content == b"0" * 1024
        assert resp.extensions["alertcheck_truncated"] is True

    @respx.mock
    async def test_small_gzip_body_is_decoded(self):
        import gzip

        respx.get("https://www.example.co.jp/g").mock(
            return_value=httpx.Response(
                200, content=gzip.compress(b"hello"), headers={"Content-Encoding": "gzip"}
            )
        )
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("https://www.example.co.jp/g", max_body=1024)
        assert resp.text == "hello"
        assert "content-encoding" not in resp.headers

    @respx.mock
    async def test_identity_encoding_is_requested(self):
        route = respx.get("https://www.example.co.jp/i").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            await client.get("https://www.example.co.jp/i", max_body=10)
        assert route.calls.last.request.headers["accept-encoding"] == "identity"


class TestPerRequestRedirects:
    @respx.mock
    async def test_zero_returns_the_redirect_itself(self):
        respx.get("http://www.example.co.jp/").mock(
            return_value=httpx.Response(301, headers={"Location": "https://www.example.co.jp/"})
        )
        target = respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200))
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard) as client:
            resp = await client.get("http://www.example.co.jp/", redirects=0)
        assert resp.status_code == 301
        assert not target.called


class TestUrlCredentials:
    async def test_unverified_client_refuses_userinfo(self):
        guard = ScopeGuard(make_scope(), resolver=public_resolver())
        async with GuardedHttpClient(guard, verify=False) as client:
            with pytest.raises(ValueError, match="credentials"):
                await client.get("https://user:pw@www.example.co.jp/")
