import ssl

import httpx
import respx

from alertcheck.checks.network.base import HttpCheck, fetch, http_targets
from alertcheck.core.models import Severity


class TestHttpTargets:
    def test_urls_domains_and_hosts(self, make_ctx):
        ctx = make_ctx(
            targets={
                "urls": ["https://shop.other.example/app/"],
                "domains": ["example.co.jp"],
                "hosts": ["198.51.100.7", "2001:db8::1"],
            }
        )
        urls = [t.url for t in http_targets(ctx)]
        assert urls == [
            "https://shop.other.example/app/",
            "https://example.co.jp/",
            "https://198.51.100.7/",
            "https://[2001:db8::1]/",
        ]

    def test_only_explicit_urls_disable_http_fallback(self, make_ctx):
        ctx = make_ctx(targets={"urls": ["https://a.example/"], "domains": ["b.example"]})
        fallback = {t.url: t.http_fallback for t in http_targets(ctx)}
        assert fallback == {"https://a.example/": False, "https://b.example/": True}

    def test_excluded_and_duplicate_targets_are_dropped(self, make_ctx):
        ctx = make_ctx(
            targets={"urls": ["https://example.co.jp/"], "domains": ["example.co.jp"]},
            exclude=["https://example.co.jp/"],
        )
        assert http_targets(ctx) == []

    def test_discovered_hosts_are_added(self, make_ctx):
        ctx = make_ctx(targets={"domains": ["example.co.jp"]})
        ctx.artifacts["discovery"] = {"hosts": ["www.example.co.jp", "evil.test"]}
        urls = [t.url for t in http_targets(ctx)]
        assert urls == ["https://example.co.jp/", "https://www.example.co.jp/"]

    def test_no_targets(self, make_ctx):
        assert http_targets(make_ctx(targets={})) == []


class TestFetch:
    @respx.mock
    async def test_certificate_error_falls_back_to_unverified(self, make_ctx):
        ctx = make_ctx()
        err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        err.__cause__ = ssl.SSLCertVerificationError("self signed")
        route = respx.get("https://www.example.co.jp/")
        route.side_effect = [err, httpx.Response(200, text="ok")]
        resp = await fetch(ctx, "https://www.example.co.jp/")
        assert resp.text == "ok"
        assert resp.extensions["alertcheck_unverified"] is True
        await ctx.aclose()

    @respx.mock
    async def test_other_connect_errors_propagate(self, make_ctx):
        ctx = make_ctx()
        respx.get("https://www.example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
        try:
            await fetch(ctx, "https://www.example.co.jp/")
        except httpx.ConnectError:
            pass
        else:
            raise AssertionError("expected ConnectError")
        await ctx.aclose()


class DummyCheck(HttpCheck):
    id = "http.dummy"
    ipa_items = ["A-6"]

    async def inspect(self, ctx, target, response):
        return [
            self.finding(
                kind="k",
                target=target.url,
                severity=Severity.low,
                ipa_items=["A-6"],
                title="t",
                description="d",
                remediation="r",
            )
        ]


class TestHttpCheck:
    def test_plan_without_targets_is_skipped(self, make_ctx):
        cov = DummyCheck().plan(make_ctx(targets={}))
        assert [c.status for c in cov] == ["skipped_no_input"]

    def test_plan_lists_targets(self, make_ctx):
        cov = DummyCheck().plan(make_ctx())
        assert [(c.status, c.target) for c in cov] == [("executed", "https://www.example.co.jp/")]

    @respx.mock
    async def test_run_collects_findings_and_isolates_errors(self, make_ctx):
        ctx = make_ctx(targets={"urls": ["https://a.example/", "https://b.example/"]})
        respx.get("https://a.example/").mock(return_value=httpx.Response(200))
        respx.get("https://b.example/").mock(side_effect=httpx.ConnectError("refused"))
        result = await DummyCheck().run(ctx)
        await ctx.aclose()
        assert [f.target for f in result.findings] == ["https://a.example/"]
        status = {c.target: c.status for c in result.coverage}
        assert status == {"https://a.example/": "executed", "https://b.example/": "error"}

    @respx.mock
    async def test_http_fallback_for_auto_targets(self, make_ctx):
        ctx = make_ctx(targets={"domains": ["example.co.jp"]})
        respx.get("https://example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
        respx.get("http://example.co.jp/").mock(return_value=httpx.Response(200))
        result = await DummyCheck().run(ctx)
        await ctx.aclose()
        assert result.coverage[0].status == "executed"
        assert "http://example.co.jp/" in result.coverage[0].detail


@respx.mock
async def test_untrusted_host_is_remembered(make_ctx):
    ctx = make_ctx()
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]")
    route = respx.get(url__startswith="https://www.example.co.jp/")
    route.side_effect = [err, httpx.Response(200), httpx.Response(200)]
    await fetch(ctx, "https://www.example.co.jp/a")
    await fetch(ctx, "https://www.example.co.jp/b")
    assert route.call_count == 3  # one failed verified attempt, then unverified only
    await ctx.aclose()
