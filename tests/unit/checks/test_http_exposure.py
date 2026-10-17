import gzip

import httpx
import pytest
import respx

from alertcheck.checks.network.http_exposure import HttpExposureCheck, load_paths

URL = "https://www.example.co.jp/"
NOT_FOUND = httpx.Response(404, text="<html><body>Not Found</body></html>")


async def run(make_ctx, routes, *, fallback=NOT_FOUND, url=URL, base=None):
    ctx = make_ctx(targets={"urls": [url]})
    respx.get(url).mock(return_value=base or httpx.Response(200, text="<html>top</html>"))
    for path, response in routes.items():
        respx.get(url + path).mock(return_value=response)
    respx.route().mock(return_value=fallback)
    result = await HttpExposureCheck().run(ctx)
    await ctx.aclose()
    return result


def found(result):
    return {(f.evidence["path"], f.evidence["kind"], f.severity.value) for f in result.findings}


class TestPathList:
    def test_bundled_list_is_valid(self):
        paths = load_paths()
        assert len(paths) >= 140
        names = [p.path for p in paths]
        assert len(names) == len(set(names))
        assert not any(n.startswith("/") for n in names)

    def test_every_entry_has_a_validator(self):
        assert all(p.match.has_rule() for p in load_paths())


@respx.mock
async def test_nothing_exposed(make_ctx):
    result = await run(make_ctx, {})
    assert result.findings == []
    assert result.coverage[0].status == "executed"


@respx.mock
async def test_soft_404_site_reports_nothing(make_ctx):
    page = "<html><head><title>Shop</title></head><body>Welcome to our shop</body></html>"
    result = await run(make_ctx, {}, fallback=httpx.Response(200, text=page))
    assert result.findings == []


@respx.mock
async def test_env_file_is_critical_and_masked(make_ctx):
    env = "APP_KEY=base64:abc\nDB_PASSWORD=s3cr3t\n# comment\nMAIL_HOST=smtp.example\n"
    result = await run(make_ctx, {".env": httpx.Response(200, text=env)})
    f = next(f for f in result.findings if f.evidence["path"] == ".env")
    assert f.severity.value == "critical"
    assert f.ipa_items == ["A-1", "D-2"]
    assert f.evidence["keys"] == ["APP_KEY", "DB_PASSWORD", "MAIL_HOST"]
    assert "s3cr3t" not in str(f.evidence)
    assert "base64:abc" not in str(f.evidence)


@respx.mock
async def test_env_path_returning_html_is_ignored(make_ctx):
    html = "<!DOCTYPE html><html><body>Custom error page with FOO=bar text</body></html>"
    assert (await run(make_ctx, {".env": httpx.Response(200, text=html)})).findings == []


@respx.mock
async def test_env_path_with_unrelated_text_is_ignored(make_ctx):
    assert (await run(make_ctx, {".env": httpx.Response(200, text="hello world")})).findings == []


@respx.mock
async def test_git_head(make_ctx):
    result = await run(make_ctx, {".git/HEAD": httpx.Response(200, text="ref: refs/heads/main\n")})
    assert (".git/HEAD", "vcs", "critical") in found(result)


@respx.mock
async def test_sql_dump_is_read_partially(make_ctx):
    dump = (
        "-- MySQL dump 10.13\nCREATE TABLE users (id int);\n"
        + "INSERT INTO users VALUES (1);\n" * 50_000
    )
    result = await run(make_ctx, {"dump.sql": httpx.Response(200, text=dump)})
    f = next(f for f in result.findings if f.evidence["path"] == "dump.sql")
    assert f.severity.value == "critical"
    assert f.evidence["truncated"] is True
    assert "INSERT" not in str(f.evidence)


@respx.mock
async def test_backup_archive_by_magic_bytes(make_ctx):
    archive = gzip.compress(b"x" * 100)
    result = await run(
        make_ctx,
        {
            "backup.tar.gz": httpx.Response(
                200, content=archive, headers={"content-type": "application/gzip"}
            )
        },
    )
    assert ("backup.tar.gz", "backup_archive", "high") in found(result)


@respx.mock
async def test_archive_path_returning_text_is_ignored(make_ctx):
    assert (
        await run(make_ctx, {"backup.zip": httpx.Response(200, text="not a zip")})
    ).findings == []


@respx.mock
async def test_admin_login_form(make_ctx):
    form = '<html><form method="post"><input type="password" name="pw"></form></html>'
    result = await run(make_ctx, {"wp-login.php": httpx.Response(200, text=form)})
    assert ("wp-login.php", "admin_panel", "medium") in found(result)


@respx.mock
async def test_admin_behind_basic_auth_is_low(make_ctx):
    resp = httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="admin"'})
    result = await run(make_ctx, {"phpmyadmin/": resp})
    assert ("phpmyadmin/", "admin_panel", "low") in found(result)


@respx.mock
async def test_admin_redirect_to_login_page_is_followed(make_ctx):
    form = '<html><input type="password"></html>'
    routes = {
        "wp-admin/": httpx.Response(302, headers={"Location": "/wp-login.php"}),
        "wp-login.php": httpx.Response(200, text=form),
    }
    result = await run(make_ctx, routes)
    paths = {p for p, _, _ in found(result)}
    assert {"wp-admin/", "wp-login.php"} <= paths


@respx.mock
async def test_secret_redirected_to_login_is_not_reported(make_ctx):
    routes = {".env": httpx.Response(302, headers={"Location": "/login"})}
    assert (await run(make_ctx, routes)).findings == []


@respx.mock
async def test_directory_listing(make_ctx):
    listing = (
        "<html><head><title>Index of /uploads</title></head>"
        "<body><h1>Index of /uploads</h1></body></html>"
    )
    result = await run(make_ctx, {"uploads/": httpx.Response(200, text=listing)})
    assert ("uploads/", "dir_listing", "medium") in found(result)


@respx.mock
async def test_directory_listing_on_base_page(make_ctx):
    listing = "<html><title>Index of /</title></html>"
    result = await run(make_ctx, {}, base=httpx.Response(200, text=listing))
    assert ("", "dir_listing", "medium") in found(result)


@respx.mock
async def test_phpinfo(make_ctx):
    page = "<html><title>PHP 7.4.3 - phpinfo()</title><h1>PHP Version 7.4.3</h1></html>"
    result = await run(make_ctx, {"phpinfo.php": httpx.Response(200, text=page)})
    assert ("phpinfo.php", "info_page", "medium") in found(result)


@respx.mock
async def test_url_prefix_target_probes_under_prefix(make_ctx):
    url = "https://www.example.co.jp/app/"
    result = await run(make_ctx, {".env": httpx.Response(200, text="A=1\n")}, url=url)
    f = next(f for f in result.findings if f.evidence["path"] == ".env")
    assert f.target == "https://www.example.co.jp/app/.env"


@respx.mock
async def test_finding_ids_differ_per_path(make_ctx):
    routes = {
        ".env": httpx.Response(200, text="A=1\n"),
        ".env.local": httpx.Response(200, text="B=2\n"),
    }
    ids = [f.id for f in (await run(make_ctx, routes)).findings]
    assert len(ids) == len(set(ids)) == 2


@pytest.mark.parametrize("status", [403, 500, 301])
@respx.mock
async def test_non_200_secret_is_ignored(make_ctx, status):
    resp = httpx.Response(status, text="A=1\n", headers={"Location": "/x"} if status == 301 else {})
    assert (await run(make_ctx, {".env": resp})).findings == []


@respx.mock
async def test_catch_all_401_is_not_an_admin_panel(make_ctx):
    challenge = httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="site"'})
    result = await run(make_ctx, {}, fallback=challenge)
    assert result.findings == []


@respx.mock
async def test_auth_scheme_is_recorded(make_ctx):
    resp = httpx.Response(401, headers={"WWW-Authenticate": 'Digest realm="admin", nonce="x"'})
    result = await run(make_ctx, {"phpmyadmin/": resp})
    f = next(f for f in result.findings if f.evidence["path"] == "phpmyadmin/")
    assert f.evidence["auth"] == "digest"


@respx.mock
async def test_failed_probes_are_counted(make_ctx):
    ctx = make_ctx(targets={"urls": [URL]})
    respx.get(URL).mock(return_value=httpx.Response(200, text="<html>top</html>"))
    respx.route().mock(side_effect=httpx.ReadTimeout("slow"))
    result = await HttpExposureCheck().run(ctx)
    await ctx.aclose()
    assert result.coverage[0].status == "error"
    assert "probes failed" in result.coverage[0].detail


@respx.mock
async def test_query_in_target_url_does_not_move_probe_base(make_ctx):
    url = "https://www.example.co.jp/app/?lang=ja"
    ctx = make_ctx(targets={"urls": [url]})
    respx.get(url).mock(return_value=httpx.Response(200, text="<html>top</html>"))
    env = respx.get("https://www.example.co.jp/app/.env").mock(
        return_value=httpx.Response(200, text="A=1\n")
    )
    respx.route().mock(return_value=NOT_FOUND)
    result = await HttpExposureCheck().run(ctx)
    await ctx.aclose()
    assert env.called
    assert any(f.evidence["path"] == ".env" for f in result.findings)


def test_soft_404_comparison_is_bounded():
    import time

    from alertcheck.checks.network.http_exposure import _Baseline, _normalize

    body = "ab" * 200_000
    baseline = _Baseline([(200, _normalize(body), "x")])
    resp = httpx.Response(200, text="ab" * 199_000 + "c" * 2000)
    start = time.perf_counter()
    for _ in range(20):
        baseline.is_soft_404(resp, "p")
    assert time.perf_counter() - start < 2.0
