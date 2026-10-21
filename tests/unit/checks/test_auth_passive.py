import httpx
import respx

from alertcheck.checks.network.auth_passive import AuthPassiveCheck

FORM = (
    '<html><body>{extra}<form method="post" action="{action}">'
    '<input name="u"><input type="password" name="p"></form></body></html>'
)


async def run(make_ctx, base_url, page):
    ctx = make_ctx(targets={"urls": [base_url]})
    respx.get(base_url).mock(return_value=httpx.Response(200, text=page))
    respx.route().mock(return_value=httpx.Response(404, text="nf"))
    result = await AuthPassiveCheck().run(ctx)
    await ctx.aclose()
    return result


def kinds(result):
    return {(f.evidence["kind"], f.severity.value) for f in result.findings}


@respx.mock
async def test_login_over_http_is_high(make_ctx):
    result = await run(
        make_ctx, "http://www.example.co.jp/", FORM.format(action="/login", extra="")
    )
    assert ("login_over_http", "high") in kinds(result)
    f = next(f for f in result.findings if f.evidence["kind"] == "login_over_http")
    assert f.ipa_items == ["A-2"]


@respx.mock
async def test_https_page_posting_to_http_is_high(make_ctx):
    page = FORM.format(action="http://www.example.co.jp/login", extra="")
    result = await run(make_ctx, "https://www.example.co.jp/", page)
    assert ("login_over_http", "high") in kinds(result)


@respx.mock
async def test_https_login_without_mfa_hint_is_info(make_ctx):
    result = await run(
        make_ctx, "https://www.example.co.jp/", FORM.format(action="/login", extra="")
    )
    assert kinds(result) == {("mfa_not_mentioned", "info")}
    assert result.artifacts["login_pages"] == {
        "https://www.example.co.jp/": ["https://www.example.co.jp/"]
    }


@respx.mock
async def test_mfa_wording_suppresses_info(make_ctx):
    page = FORM.format(
        action="/login", extra="<p>ログイン後にワンタイムパスワード（二段階認証）を入力します</p>"
    )
    result = await run(make_ctx, "https://www.example.co.jp/", page)
    assert result.findings == []


@respx.mock
async def test_login_path_is_probed(make_ctx):
    ctx = make_ctx(targets={"urls": ["https://www.example.co.jp/"]})
    respx.get("https://www.example.co.jp/").mock(
        return_value=httpx.Response(200, text="<html>top</html>")
    )
    respx.get("https://www.example.co.jp/login").mock(
        return_value=httpx.Response(200, text=FORM.format(action="", extra=""))
    )
    respx.route().mock(return_value=httpx.Response(404))
    result = await AuthPassiveCheck().run(ctx)
    await ctx.aclose()
    assert any(f.target == "https://www.example.co.jp/login" for f in result.findings)


@respx.mock
async def test_no_password_form_no_findings(make_ctx):
    result = await run(
        make_ctx, "https://www.example.co.jp/", "<html><form><input name=q></form></html>"
    )
    assert result.findings == []


@respx.mock
async def test_login_redirect_to_other_origin_is_not_followed(make_ctx):
    ctx = make_ctx(targets={"urls": ["https://www.example.co.jp/"]})
    respx.get("https://www.example.co.jp/").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    respx.get("https://www.example.co.jp/login").mock(
        return_value=httpx.Response(302, headers={"Location": "https://idp.vendor.test/login"})
    )
    idp = respx.get("https://idp.vendor.test/login").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))
    await AuthPassiveCheck().run(ctx)
    await ctx.aclose()
    assert not idp.called
