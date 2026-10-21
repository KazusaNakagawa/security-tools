import httpx
import respx

from alertcheck.checks.network.discovery import DiscoveryCheck

CRT = [
    {"name_value": "www.example.co.jp\nexample.co.jp"},
    {"name_value": "shop.example.co.jp"},
    {"name_value": "*.example.co.jp"},
    {"name_value": "old.example.co.jp"},
    {"name_value": "evil.test"},
    {"name_value": "legacy.example.co.jp"},
]


def resolver():
    table = {
        "example.co.jp": ["93.184.216.34"],
        "www.example.co.jp": ["93.184.216.34"],
        "shop.example.co.jp": ["93.184.216.40"],
        "legacy.example.co.jp": ["93.184.216.41"],
        "old.example.co.jp": [],  # certificate exists but the name no longer resolves
        "gone.example.co.jp": [],
    }

    async def resolve(host):
        return table.get(host, [])

    return resolve


async def run(make_ctx, tmp_path, inventory=None, crt_status=200, **scope):
    if inventory is not None:
        (tmp_path / "assets.csv").write_text(inventory, encoding="utf-8")
        scope["asset_inventory"] = "assets.csv"
    ctx = make_ctx(targets={"domains": ["example.co.jp"]}, resolver=resolver(), **scope)
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(crt_status, json=CRT if crt_status == 200 else None)
    )
    check = DiscoveryCheck()
    result = await check.run(ctx)
    await ctx.aclose()
    return check.plan(ctx), result


def kinds(result):
    return {(f.evidence["kind"], f.evidence.get("host"), f.severity.value) for f in result.findings}


@respx.mock
async def test_hosts_missing_from_inventory_are_medium(make_ctx, tmp_path):
    inventory = "host,owner\nexample.co.jp,IT\nwww.example.co.jp,IT\ngone.example.co.jp,IT\n"
    _, result = await run(make_ctx, tmp_path, inventory=inventory, exclude=["legacy.example.co.jp"])
    found = kinds(result)
    assert ("unlisted_host", "shop.example.co.jp", "medium") in found
    assert all(h != "www.example.co.jp" for _, h, _ in found)
    assert ("unresolved_inventory_host", "gone.example.co.jp", "info") in found
    unlisted = next(f for f in result.findings if f.evidence["kind"] == "unlisted_host")
    assert unlisted.ipa_items == ["P1-1"]


@respx.mock
async def test_out_of_scope_wildcard_and_excluded_names_are_ignored(make_ctx, tmp_path):
    _, result = await run(
        make_ctx, tmp_path, inventory="host\nexample.co.jp\n", exclude=["legacy.example.co.jp"]
    )
    hosts = {f.evidence.get("host") for f in result.findings}
    assert "evil.test" not in hosts
    assert "*.example.co.jp" not in hosts
    assert "legacy.example.co.jp" not in hosts
    assert "old.example.co.jp" not in hosts  # does not resolve


@respx.mock
async def test_without_inventory_reports_discovered_hosts_as_info(make_ctx, tmp_path):
    _, result = await run(make_ctx, tmp_path)
    info = [f for f in result.findings if f.evidence["kind"] == "no_inventory"]
    assert info and info[0].severity.value == "info"
    assert "shop.example.co.jp" in info[0].evidence["hosts"]
    assert result.artifacts["hosts"] == [
        "example.co.jp",
        "legacy.example.co.jp",
        "shop.example.co.jp",
        "www.example.co.jp",
    ]


@respx.mock
async def test_inventory_accepts_urls_and_hostname_columns(make_ctx, tmp_path):
    inventory = "url\nhttps://shop.example.co.jp/cart\nhttps://www.example.co.jp/\nhttps://legacy.example.co.jp\nexample.co.jp\n"
    _, result = await run(make_ctx, tmp_path, inventory=inventory)
    assert not [f for f in result.findings if f.evidence["kind"] == "unlisted_host"]


@respx.mock
async def test_crtsh_failure_is_noted_but_not_fatal(make_ctx, tmp_path):
    _, result = await run(make_ctx, tmp_path, inventory="host\nexample.co.jp\n", crt_status=503)
    assert result.coverage[0].status == "executed"
    assert "crt.sh" in result.coverage[0].detail


@respx.mock
async def test_missing_inventory_file_is_an_error(make_ctx, tmp_path):
    ctx = make_ctx(
        targets={"domains": ["example.co.jp"]}, resolver=resolver(), asset_inventory="nope.csv"
    )
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, json=[]))
    result = await DiscoveryCheck().run(ctx)
    await ctx.aclose()
    assert result.coverage[0].status == "error"


def test_plan_without_domains(make_ctx):
    plan = DiscoveryCheck().plan(make_ctx(targets={"hosts": ["198.51.100.7"]}))
    assert [c.status for c in plan] == ["skipped_no_input"]
