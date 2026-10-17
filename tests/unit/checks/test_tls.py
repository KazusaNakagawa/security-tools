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
async def test_nothing_reachable_is_an_error(make_ctx):
    def down(host, port):
        return TlsScanResult(host=host, port=port, error="connection refused")

    result = await run(make_ctx, FakeScanner(down), http_redirect=None)
    assert result.findings == []
    assert result.coverage[0].status == "error"


@respx.mock
async def test_targets_are_deduplicated_per_host_and_port(make_ctx):
    scanner = FakeScanner()
    targets = {
        "urls": [
            "https://www.example.co.jp/a/",
            "https://www.example.co.jp/b/",
            "https://www.example.co.jp:8443/",
        ]
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
async def test_plain_http_targets_are_not_tls_scanned(make_ctx):
    scanner = FakeScanner()
    ctx = make_ctx(targets={"urls": ["http://www.example.co.jp/"]})
    plan = TlsCheck(scanner=scanner, now=lambda: NOW).plan(ctx)
    assert [c.status for c in plan] == ["skipped_no_input"]
    assert scanner.calls == []


@respx.mock
async def test_url_prefix_target_skips_http_redirect_check(make_ctx):
    """http:// is a different origin from an https:// URL-prefix target, so it is not probed."""
    scanner = FakeScanner()
    route = respx.get("http://www.example.co.jp/").mock(return_value=httpx.Response(200))
    ctx = make_ctx(targets={"urls": ["https://www.example.co.jp/"]})
    result = await TlsCheck(scanner=scanner, now=lambda: NOW).run(ctx)
    await ctx.aclose()
    assert not route.called
    assert result.findings == []


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


def test_default_scanner_uses_configured_concurrency(make_ctx, monkeypatch):
    calls = []

    def fake_scan(host, port, ip, *, concurrency):
        calls.append(concurrency)
        return good(host, port)

    monkeypatch.setattr("alertcheck.adapters.sslyze_scan.scan", fake_scan)
    ctx = make_ctx(targets={"urls": ["https://www.example.co.jp/"]}, limits={"concurrency": 3})
    import asyncio

    asyncio.run(TlsCheck(now=lambda: NOW).run(ctx))
    assert calls == [3]
