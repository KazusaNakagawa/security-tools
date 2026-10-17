import httpx
import pytest
import respx

from alertcheck.checks.network.http_errors import PROBES, HttpErrorsCheck

URL = "https://www.example.co.jp/"


async def run(make_ctx, probe_response, *, url=URL):
    ctx = make_ctx(targets={"urls": [url]})
    respx.get(url).mock(return_value=httpx.Response(200, text="<html>top</html>"))
    respx.route().mock(return_value=probe_response)
    result = await HttpErrorsCheck().run(ctx)
    await ctx.aclose()
    return result, respx.calls


def kinds(result):
    return {(f.evidence["kind"], f.severity.value) for f in result.findings}


@respx.mock
async def test_clean_error_pages(make_ctx):
    result, _ = await run(make_ctx, httpx.Response(404, text="<html>Not Found</html>"))
    assert result.findings == []


@pytest.mark.parametrize(
    "body,framework",
    [
        ('Traceback (most recent call last):\n  File "/app/views.py", line 3', "python"),
        ("java.lang.NullPointerException\n\tat com.example.Foo.bar(Foo.java:42)", "java"),
        (
            "<b>Fatal error</b>: Uncaught Exception in /var/www/html/index.php:12\nStack trace:",
            "php",
        ),
        ("TypeError: x is undefined\n    at Object.<anonymous> (/srv/app/index.js:10:5)", "node"),
        ("<title>Server Error in '/' Application.</title> System.NullReferenceException", "dotnet"),
        ("You're seeing this error because you have <code>DEBUG = True</code>", "django"),
        ("<title>Whoops! There was an error.</title>", "laravel"),
        ("ActionController::RoutingError (No route matches", "rails"),
    ],
)
@respx.mock
async def test_stack_traces(make_ctx, body, framework):
    result, _ = await run(make_ctx, httpx.Response(500, text=body))
    assert ("stack_trace", "medium") in kinds(result)
    f = next(f for f in result.findings if f.evidence["kind"] == "stack_trace")
    assert f.evidence["framework"] == framework
    assert f.ipa_items == ["A-6"]


@pytest.mark.parametrize(
    "body",
    [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL",
        "SQLSTATE[42000]: Syntax error or access violation",
        "ORA-01756: quoted string not properly terminated",
        "PG::SyntaxError: ERROR:  unterminated quoted string at or near",
        "Unclosed quotation mark after the character string",
        "SQLite3::SQLException: unrecognized token",
    ],
)
@respx.mock
async def test_sql_errors_are_high(make_ctx, body):
    result, _ = await run(make_ctx, httpx.Response(500, text=body))
    assert ("sql_error", "high") in kinds(result)


@respx.mock
async def test_one_finding_per_kind_per_target(make_ctx):
    body = "Traceback (most recent call last):\nYou have an error in your SQL syntax"
    result, _ = await run(make_ctx, httpx.Response(500, text=body))
    assert sorted(f.evidence["kind"] for f in result.findings) == ["sql_error", "stack_trace"]


@respx.mock
async def test_probes_are_get_only_and_non_destructive(make_ctx):
    _, calls = await run(make_ctx, httpx.Response(404))
    requests = [c.request for c in calls]
    assert all(r.method == "GET" for r in requests)
    assert len(requests) == 1 + len(PROBES)
    for r in requests:
        q = str(r.url).lower()
        for bad in ("union", "select", "sleep(", "<script", "drop ", "or 1=1", "../"):
            assert bad not in q


@respx.mock
async def test_excerpt_is_short(make_ctx):
    body = "x" * 5000 + "Traceback (most recent call last):" + "y" * 5000
    result, _ = await run(make_ctx, httpx.Response(500, text=body))
    assert len(result.findings[0].evidence["excerpt"]) <= 300


@respx.mock
async def test_url_prefix_target(make_ctx):
    url = "https://www.example.co.jp/app/"
    result, calls = await run(make_ctx, httpx.Response(404), url=url)
    assert all(str(c.request.url).startswith(url) for c in calls)


@respx.mock
async def test_failed_probes_are_counted(make_ctx):
    ctx = make_ctx(targets={"urls": [URL]})
    respx.get(URL).mock(return_value=httpx.Response(200, text="<html>top</html>"))
    respx.route().mock(side_effect=httpx.ReadTimeout("slow"))
    result = await HttpErrorsCheck().run(ctx)
    await ctx.aclose()
    assert result.coverage[0].status == "error"
    # respx's URL pattern ignores the query, so the "?..." probes hit the base route
    path_probes = sum(1 for p in PROBES if not p.startswith("?"))
    assert f"{path_probes}/{len(PROBES)} probes failed" in result.coverage[0].detail


@respx.mock
async def test_query_in_target_url_does_not_move_probe_base(make_ctx):
    url = "https://www.example.co.jp/app/?lang=ja"
    _, calls = await run(make_ctx, httpx.Response(404), url=url)
    probes = [str(c.request.url) for c in calls][1:]
    assert all(p.startswith("https://www.example.co.jp/app/") for p in probes)
    assert not any("lang=ja/" in p for p in probes)
