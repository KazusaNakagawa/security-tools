import httpx
import pytest
import respx

from alertcheck.checks.network.http_cookies import HttpCookiesCheck, parse_set_cookie

URL = "https://www.example.co.jp/"


async def run(make_ctx, cookies, url=URL):
    ctx = make_ctx(targets={"urls": [url]})
    headers = [("set-cookie", c) for c in cookies]
    respx.get(url).mock(return_value=httpx.Response(200, headers=headers))
    result = await HttpCookiesCheck().run(ctx)
    await ctx.aclose()
    return result


def summary(result):
    return {(f.evidence["cookie"], f.evidence["kind"], f.severity.value) for f in result.findings}


class TestParse:
    def test_attributes(self):
        c = parse_set_cookie("SID=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        assert c.name == "SID"
        assert c.secure and c.httponly
        assert c.samesite == "lax"

    def test_missing_attributes(self):
        c = parse_set_cookie("a=b")
        assert not c.secure and not c.httponly and c.samesite is None

    def test_value_with_equals_and_spaces(self):
        c = parse_set_cookie(" token = x=y==; secure ")
        assert c.name == "token"
        assert c.secure

    def test_empty_header(self):
        assert parse_set_cookie("") is None


@respx.mock
async def test_hardened_session_cookie_has_no_findings(make_ctx):
    assert (await run(make_ctx, ["PHPSESSID=1; Secure; HttpOnly; SameSite=Lax"])).findings == []


@respx.mock
async def test_bare_session_cookie(make_ctx):
    result = await run(make_ctx, ["JSESSIONID=1; Path=/"])
    assert summary(result) == {
        ("JSESSIONID", "cookie_secure_missing", "medium"),
        ("JSESSIONID", "cookie_httponly_missing", "medium"),
        ("JSESSIONID", "cookie_samesite_missing", "low"),
    }
    assert all(f.ipa_items == ["A-2"] for f in result.findings)


@respx.mock
async def test_samesite_none_without_secure(make_ctx):
    result = await run(make_ctx, ["connect.sid=1; HttpOnly; SameSite=None"])
    assert summary(result) == {
        ("connect.sid", "cookie_secure_missing", "medium"),
        ("connect.sid", "cookie_samesite_none_insecure", "medium"),
    }


@respx.mock
async def test_session_cookie_over_plain_http_is_flagged(make_ctx):
    result = await run(
        make_ctx, ["session=1; HttpOnly; SameSite=Lax"], url="http://www.example.co.jp/"
    )
    assert summary(result) == {("session", "cookie_secure_missing", "medium")}
    assert result.findings[0].evidence["over_http"] is True


@respx.mock
async def test_weaker_duplicate_cookie_is_judged(make_ctx):
    result = await run(
        make_ctx,
        [
            "sid=1; Secure; HttpOnly; SameSite=Lax; Path=/",
            "sid=2; Path=/admin",
        ],
    )
    assert summary(result) == {
        ("sid", "cookie_secure_missing", "medium"),
        ("sid", "cookie_httponly_missing", "medium"),
        ("sid", "cookie_samesite_missing", "low"),
    }
    assert {f.evidence["path"] for f in result.findings} == {"/admin"}


@respx.mock
async def test_identical_duplicates_are_reported_once(make_ctx):
    result = await run(make_ctx, ["sid=1; Path=/", "sid=2; Path=/"])
    assert len(result.findings) == 3


@pytest.mark.parametrize(
    "name", ["laravel_session", "ci_session", "sid", "auth_token", "remember_me", "XSRF-TOKEN"]
)
@respx.mock
async def test_session_like_names(make_ctx, name):
    result = await run(make_ctx, [f"{name}=1"])
    assert result.findings, name


@respx.mock
async def test_non_session_cookie_is_ignored(make_ctx):
    assert (await run(make_ctx, ["_ga=GA1.2.3; Path=/", "lang=ja"])).findings == []


@respx.mock
async def test_cookie_value_is_not_in_evidence(make_ctx):
    result = await run(make_ctx, ["sid=supersecretvalue"])
    assert all("supersecretvalue" not in str(f.evidence) for f in result.findings)


@respx.mock
async def test_findings_per_cookie_have_distinct_ids(make_ctx):
    result = await run(make_ctx, ["sid=1", "session=2"])
    ids = [f.id for f in result.findings]
    assert len(ids) == len(set(ids)) == 6


@respx.mock
async def test_cookies_set_during_redirect_are_checked(make_ctx):
    ctx = make_ctx(targets={"urls": [URL]})
    respx.get(URL).mock(
        return_value=httpx.Response(302, headers=[("location", "/home"), ("set-cookie", "sid=1")])
    )
    respx.get("https://www.example.co.jp/home").mock(return_value=httpx.Response(200))
    result = await HttpCookiesCheck().run(ctx)
    await ctx.aclose()
    assert {f.evidence["cookie"] for f in result.findings} == {"sid"}
