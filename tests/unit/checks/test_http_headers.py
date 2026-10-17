import httpx
import respx

from alertcheck.checks.network.http_headers import HttpHeadersCheck

URL = "https://www.example.co.jp/"

SECURE = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Server": "nginx",
}


async def run(make_ctx, headers, url=URL):
    ctx = make_ctx(targets={"urls": [url]})
    respx.get(url).mock(return_value=httpx.Response(200, headers=headers, text="<html></html>"))
    result = await HttpHeadersCheck().run(ctx)
    await ctx.aclose()
    return result


def kinds(result):
    return {f.check_id + ":" + f.title: f for f in result.findings}


def kind_set(result):
    return {f.evidence.get("kind") for f in result.findings}


@respx.mock
async def test_secure_site_has_no_findings(make_ctx):
    result = await run(make_ctx, SECURE)
    assert result.findings == []
    assert result.artifacts["banners"][URL] == {"server": "nginx", "x_powered_by": None}


@respx.mock
async def test_all_missing(make_ctx):
    result = await run(make_ctx, {})
    assert kind_set(result) == {
        "hsts_missing",
        "csp_missing",
        "clickjacking",
        "nosniff_missing",
        "referrer_policy_missing",
        "permissions_policy_missing",
    }
    sev = {f.evidence["kind"]: f.severity.value for f in result.findings}
    assert sev["csp_missing"] == "medium"
    assert sev["clickjacking"] == "medium"
    assert sev["hsts_missing"] == "medium"
    assert sev["nosniff_missing"] == "low"
    assert sev["permissions_policy_missing"] == "info"
    assert all(f.ipa_items == ["A-6"] for f in result.findings)


@respx.mock
async def test_csp_without_frame_ancestors_but_xfo_is_not_clickjackable(make_ctx):
    headers = {**SECURE, "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"}
    assert "clickjacking" not in kind_set(await run(make_ctx, headers))


@respx.mock
async def test_csp_without_frame_ancestors_and_no_xfo_is_clickjackable(make_ctx):
    headers = {**SECURE, "Content-Security-Policy": "default-src 'self'"}
    result = await run(make_ctx, headers)
    assert kind_set(result) == {"clickjacking"}


@respx.mock
async def test_report_only_csp_does_not_count(make_ctx):
    headers = {k: v for k, v in SECURE.items() if k != "Content-Security-Policy"}
    headers["Content-Security-Policy-Report-Only"] = "frame-ancestors 'none'"
    assert {"csp_missing", "clickjacking"} <= kind_set(await run(make_ctx, headers))


@respx.mock
async def test_hsts_with_zero_max_age_counts_as_missing(make_ctx):
    headers = {**SECURE, "Strict-Transport-Security": "max-age=0"}
    assert kind_set(await run(make_ctx, headers)) == {"hsts_missing"}


@respx.mock
async def test_hsts_not_required_on_plain_http(make_ctx):
    url = "http://www.example.co.jp/"
    headers = {k: v for k, v in SECURE.items() if k != "Strict-Transport-Security"}
    assert "hsts_missing" not in kind_set(await run(make_ctx, headers, url=url))


@respx.mock
async def test_version_disclosure(make_ctx):
    headers = {**SECURE, "Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "PHP/7.4.3"}
    result = await run(make_ctx, headers)
    leaks = [f for f in result.findings if f.evidence["kind"] == "version_disclosure"]
    assert {f.evidence["header"] for f in leaks} == {"server", "x-powered-by"}
    assert all(f.severity.value == "low" for f in leaks)
    assert result.artifacts["banners"][URL] == {
        "server": "Apache/2.4.49 (Unix)",
        "x_powered_by": "PHP/7.4.3",
    }


@respx.mock
async def test_product_without_version_is_not_disclosure(make_ctx):
    headers = {**SECURE, "Server": "cloudflare"}
    assert kind_set(await run(make_ctx, headers)) == set()


@respx.mock
async def test_findings_are_judged_on_final_response_after_redirect(make_ctx):
    ctx = make_ctx(targets={"urls": [URL]})
    respx.get(URL).mock(return_value=httpx.Response(301, headers={"Location": "/top"}))
    respx.get("https://www.example.co.jp/top").mock(
        return_value=httpx.Response(200, headers=SECURE)
    )
    result = await HttpHeadersCheck().run(ctx)
    await ctx.aclose()
    assert result.findings == []


@respx.mock
async def test_version_leaks_have_distinct_ids(make_ctx):
    headers = {**SECURE, "Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4.3"}
    result = await run(make_ctx, headers)
    ids = [f.id for f in result.findings]
    assert len(ids) == len(set(ids)) == 2
