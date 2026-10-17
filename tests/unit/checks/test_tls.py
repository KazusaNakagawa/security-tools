import datetime as dt

import httpx
import respx

from alertcheck.adapters.sslyze_scan import TlsScanResult
from alertcheck.checks.network.tls import TlsCheck

NOW = dt.datetime(2026, 10, 17, tzinfo=dt.UTC)


def good(host, port):
    return TlsScanResult(
        host=host,
        port=port,
        accepted_protocols={"TLSv1.2", "TLSv1.3"},
        cert_not_after=NOW + dt.timedelta(days=200),
        hostname_matches=True,
        trusted=True,
    )


class FakeScanner:
    def __init__(self, factory=good):
        self.calls = []
        self.factory = factory

    def __call__(self, host, port, ip):
        self.calls.append((host, port, ip))
        return self.factory(host, port)


async def run(make_ctx, scanner, *, targets=None, http_redirect=True, resolver=None):
    # a domain target authorizes both http:// and https:// on the host
    ctx = make_ctx(targets=targets or {"domains": ["www.example.co.jp"]}, resolver=resolver)
    if http_redirect is True:
        respx.get("http://www.example.co.jp/").mock(
            return_value=httpx.Response(301, headers={"Location": "https://www.example.co.jp/"})
        )
        respx.get("https://www.example.co.jp/").mock(return_value=httpx.Response(200))
    elif http_redirect is False:
        respx.get("http://www.example.co.jp/").mock(return_value=httpx.Response(200, text="plain"))
    else:
        respx.get("http://www.example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
    result = await TlsCheck(scanner=scanner, now=lambda: NOW).run(ctx)
    await ctx.aclose()
    return result


def kinds(result):
    return {(f.evidence["kind"], f.severity.value) for f in result.findings}


@respx.mock
async def test_good_configuration(make_ctx):
    scanner = FakeScanner()
    result = await run(make_ctx, scanner)
    assert result.findings == []
    assert result.coverage[0].status == "executed"
    assert result.coverage[0].target == "www.example.co.jp:443"


@respx.mock
async def test_scanner_receives_pinned_address(make_ctx):
    from tests.unit.checks.conftest import static_resolver

    scanner = FakeScanner()
    await run(make_ctx, scanner, resolver=static_resolver({"www.example.co.jp": ["93.184.216.34"]}))
    assert scanner.calls == [("www.example.co.jp", 443, "93.184.216.34")]


@respx.mock
async def test_unresolvable_host_is_not_scanned(make_ctx):
    async def resolve(host):
        return []

    scanner = FakeScanner()
    result = await run(make_ctx, scanner, resolver=resolve)
    assert scanner.calls == []
    assert result.coverage[0].status == "error"


@respx.mock
async def test_legacy_protocols_and_weak_ciphers(make_ctx):
    def bad(host, port):
        r = good(host, port)
        r.accepted_protocols |= {"SSLv3", "TLSv1.0", "TLSv1.1"}
        r.weak_ciphers = ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
        return r

    result = await run(make_ctx, FakeScanner(bad))
    assert kinds(result) == {
        ("legacy_ssl", "high"),
        ("legacy_tls", "medium"),
        ("weak_cipher", "medium"),
    }
    legacy = next(f for f in result.findings if f.evidence["kind"] == "legacy_tls")
    assert legacy.evidence["protocols"] == ["TLSv1.0", "TLSv1.1"]
    assert all(f.ipa_items == ["A-6", "D-4"] for f in result.findings)


@respx.mock
async def test_certificate_expired(make_ctx):
    def expired(host, port):
        r = good(host, port)
        r.cert_not_after = NOW - dt.timedelta(seconds=1)
        return r

    assert kinds(await run(make_ctx, FakeScanner(expired))) == {("cert_expired", "high")}


@respx.mock
async def test_certificate_expiring_boundary(make_ctx):
    def at(days):
        def f(host, port):
            r = good(host, port)
            r.cert_not_after = NOW + dt.timedelta(days=days)
            return r

        return f

    assert kinds(await run(make_ctx, FakeScanner(at(30)))) == {("cert_expiring", "medium")}
    assert kinds(await run(make_ctx, FakeScanner(at(31)))) == set()


@respx.mock
async def test_hostname_mismatch_suppresses_untrusted(make_ctx):
    def mismatch(host, port):
        r = good(host, port)
        r.hostname_matches = False
        r.trusted = False
        return r

    assert kinds(await run(make_ctx, FakeScanner(mismatch))) == {("cert_hostname_mismatch", "high")}


@respx.mock
async def test_untrusted_chain(make_ctx):
    def untrusted(host, port):
        r = good(host, port)
        r.trusted = False
        return r

    assert kinds(await run(make_ctx, FakeScanner(untrusted))) == {("cert_untrusted", "medium")}


@respx.mock
async def test_no_https_redirect(make_ctx):
    result = await run(make_ctx, FakeScanner(), http_redirect=False)
    assert kinds(result) == {("no_https_redirect", "medium")}
    assert result.findings[0].ipa_items == ["D-4"]


@respx.mock
async def test_closed_http_port_is_fine(make_ctx):
    assert (await run(make_ctx, FakeScanner(), http_redirect=None)).findings == []


@respx.mock
async def test_https_unavailable_but_http_serves(make_ctx):
    def down(host, port):
        return TlsScanResult(host=host, port=port, error="connection refused")

    result = await run(make_ctx, FakeScanner(down), http_redirect=False)
    assert kinds(result) == {("https_unavailable", "high")}
    assert result.coverage[0].status == "executed"


@respx.mock
async def test_domain_with_nothing_reachable_is_skipped(make_ctx):
    def down(host, port):
        return TlsScanResult(host=host, port=port, error="connection refused")

    result = await run(make_ctx, FakeScanner(down), http_redirect=None)
    assert result.findings == []
    assert result.coverage[0].status == "skipped_no_input"  # explicit URLs still error


@respx.mock
async def test_targets_are_deduplicated_per_host_and_port(make_ctx):
    scanner = FakeScanner()
    targets = {
        "domains": ["www.example.co.jp"],
        "urls": [
            "https://www.example.co.jp/a/",
            "https://www.example.co.jp/b/",
            "https://www.example.co.jp:8443/",
        ],
    }
    respx.get(url__regex=r"http://www\.example\.co\.jp(:8443)?/.*").mock(
        side_effect=httpx.ConnectError("refused")
    )
    await run(make_ctx, scanner, targets=targets, http_redirect="skip")
    assert sorted(c[:2] for c in scanner.calls) == [
        ("www.example.co.jp", 443),
        ("www.example.co.jp", 8443),
    ]


@respx.mock
async def test_plain_http_target_gets_redirect_check_only(make_ctx):
    scanner = FakeScanner()
    ctx = make_ctx(targets={"urls": ["http://www.example.co.jp/"]})
    respx.get("http://www.example.co.jp/").mock(return_value=httpx.Response(200, text="plain"))
    check = TlsCheck(scanner=scanner, now=lambda: NOW)
    assert [c.status for c in check.plan(ctx)] == ["executed"]
    result = await check.run(ctx)
    await ctx.aclose()
    assert scanner.calls == []
    assert kinds(result) == {("no_https_redirect", "medium")}


@respx.mock
async def test_plain_http_target_redirecting_to_https_is_fine(make_ctx):
    ctx = make_ctx(targets={"urls": ["http://www.example.co.jp/"]})
    respx.get("http://www.example.co.jp/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.example.co.jp/"})
    )
    result = await TlsCheck(scanner=FakeScanner(), now=lambda: NOW).run(ctx)
    await ctx.aclose()
    assert result.findings == []


@respx.mock
async def test_url_prefix_only_target_is_not_tls_scanned(make_ctx):
    """A URL prefix authorizes that path, not a host-wide TLS scan."""
    scanner = FakeScanner()
    ctx = make_ctx(targets={"urls": ["https://www.example.co.jp/app/"]})
    check = TlsCheck(scanner=scanner, now=lambda: NOW)
    plan = check.plan(ctx)
    assert [c.status for c in plan] == ["skipped_by_option"]
    assert "URL-prefix" in plan[0].detail
    result = await check.run(ctx)
    await ctx.aclose()
    assert scanner.calls == []
    assert result.coverage[0].status == "skipped_by_option"


@respx.mock
async def test_scanner_exception_is_isolated_per_endpoint(make_ctx):
    def flaky(host, port):
        if port == 8443:
            raise RuntimeError("unexpected sslyze status")
        return good(host, port)

    targets = {"domains": ["www.example.co.jp"], "urls": ["https://www.example.co.jp:8443/"]}
    result = await run(make_ctx, FakeScanner(flaky), targets=targets, http_redirect=None)
    status = {c.target: (c.status, c.detail) for c in result.coverage}
    assert status["www.example.co.jp:443"][0] == "executed"
    assert status["www.example.co.jp:8443"][0] == "error"
    assert "unexpected sslyze status" in status["www.example.co.jp:8443"][1]


@respx.mock
async def test_redirect_to_dead_https_is_reported(make_ctx):
    def down(host, port):
        return TlsScanResult(host=host, port=port, error="connection refused")

    ctx = make_ctx(targets={"domains": ["www.example.co.jp"]})
    respx.get("http://www.example.co.jp/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.example.co.jp/"})
    )
    respx.get("https://www.example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
    result = await TlsCheck(scanner=FakeScanner(down), now=lambda: NOW).run(ctx)
    await ctx.aclose()
    assert kinds(result) == {("https_unavailable", "high")}
    assert result.findings[0].evidence["http_redirects_to_https"] is True


@respx.mock
async def test_endpoint_scans_do_not_overlap(make_ctx):
    import threading
    import time

    lock = threading.Lock()
    state = {"active": 0, "peak": 0}

    def slow(host, port):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.05)
        with lock:
            state["active"] -= 1
        return good(host, port)

    targets = {
        "domains": ["www.example.co.jp"],
        "urls": ["https://www.example.co.jp:8443/", "https://www.example.co.jp:9443/"],
    }
    await run(make_ctx, FakeScanner(slow), targets=targets, http_redirect=None)
    assert state["peak"] == 1


@respx.mock
async def test_tls_scan_is_recorded_in_audit_log(make_ctx):
    import json

    ctx = make_ctx(targets={"domains": ["www.example.co.jp"]})
    respx.get("http://www.example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
    await TlsCheck(scanner=FakeScanner(), now=lambda: NOW).run(ctx)
    await ctx.aclose()
    events = [json.loads(line) for line in ctx.request_log.read_text().splitlines()]
    scan = next(e for e in events if e["event"] == "tls_scan")
    assert scan["host"] == "www.example.co.jp" and scan["port"] == 443
    assert scan["address"] == "93.184.216.34"


@respx.mock
def test_default_scanner_uses_configured_concurrency(make_ctx, monkeypatch):
    # keep the HTTP redirect probe off the real network
    respx.get("http://www.example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
    calls = []

    def fake_scan(host, port, ip, *, concurrency):
        calls.append(concurrency)
        return good(host, port)

    monkeypatch.setattr("alertcheck.adapters.sslyze_scan.scan", fake_scan)
    ctx = make_ctx(targets={"domains": ["www.example.co.jp"]}, limits={"concurrency": 3})
    import asyncio

    asyncio.run(TlsCheck(now=lambda: NOW).run(ctx))
    assert calls == [3]


@respx.mock
async def test_host_without_any_web_service_is_skipped(make_ctx):
    def down(host, port):
        return TlsScanResult(host=host, port=port, error="connection refused")

    ctx = make_ctx(targets={"hosts": ["198.51.100.7"]})
    respx.get("http://198.51.100.7/").mock(side_effect=httpx.ConnectError("refused"))
    result = await TlsCheck(scanner=FakeScanner(down), now=lambda: NOW).run(ctx)
    await ctx.aclose()
    assert result.findings == []
    assert result.coverage[0].status == "skipped_no_input"


@respx.mock
async def test_explicit_https_url_down_is_still_an_error(make_ctx):
    def down(host, port):
        return TlsScanResult(host=host, port=port, error="connection refused")

    ctx = make_ctx(
        targets={"domains": ["www.example.co.jp"], "urls": ["https://www.example.co.jp:8443/"]}
    )
    respx.get("http://www.example.co.jp/").mock(side_effect=httpx.ConnectError("refused"))
    result = await TlsCheck(scanner=FakeScanner(down), now=lambda: NOW).run(ctx)
    await ctx.aclose()
    status = {c.target: c.status for c in result.coverage}
    assert status["www.example.co.jp:8443"] == "error"
    assert status["www.example.co.jp:443"] == "skipped_no_input"
