import datetime as dt
import shutil
from pathlib import Path

import httpx
import pytest
import respx

from alertcheck.checks.network.vuln_version import VPN_PROBES, VulnVersionCheck

URL = "https://www.example.co.jp/"
FIX = Path(__file__).parents[2] / "fixtures" / "tools"
TODAY = dt.date(2026, 10, 17)


@pytest.fixture
def cache(tmp_path):
    shutil.copy(FIX / "kev.json", tmp_path / "kev.json")
    return tmp_path


async def run(make_ctx, cache, *, headers=None, body="<html></html>", routes=None, fallback=None):
    ctx = make_ctx(targets={"urls": [URL]})
    respx.get(URL).mock(return_value=httpx.Response(200, headers=headers or {}, text=body))
    for path, resp in (routes or {}).items():
        respx.get(URL + path).mock(return_value=resp)
    respx.route().mock(return_value=fallback or httpx.Response(404, text="nf"))
    result = await VulnVersionCheck(cache=cache, today=TODAY).run(ctx)
    await ctx.aclose()
    return result


def kinds(result):
    return {
        (f.evidence["kind"], f.evidence.get("product"), f.severity.value) for f in result.findings
    }


@respx.mock
async def test_eol_server_and_language(make_ctx, cache):
    result = await run(
        make_ctx, cache, headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
    )
    assert ("eol_software", "nginx", "high") in kinds(result)
    assert ("eol_software", "php", "high") in kinds(result)
    php = next(f for f in result.findings if f.evidence.get("product") == "php")
    assert php.ipa_items == ["P1-4"]
    assert php.evidence["version"] == "7.4.3"


@respx.mock
async def test_supported_version_has_no_eol_finding(make_ctx, cache):
    result = await run(make_ctx, cache, headers={"X-Powered-By": "PHP/8.3.1"})
    assert not any(f.evidence["kind"] == "eol_software" for f in result.findings)


@respx.mock
async def test_kev_product_hint(make_ctx, cache):
    result = await run(make_ctx, cache, headers={"Server": "Apache/2.4.49 (Unix)"})
    hint = next(f for f in result.findings if f.evidence["kind"] == "kev_product")
    assert hint.severity.value == "medium"
    assert hint.evidence["kev_cves"] == ["CVE-2021-41773"]
    assert hint.evidence["version"] == "2.4.49"


@respx.mock
async def test_generator_meta(make_ctx, cache):
    # endoflife.date keeps every WordPress branch "supported", so use Drupal 7 (EOL 2025-01-05)
    body = (
        '<html><head><meta name="Generator" content="Drupal 7 (https://www.drupal.org)" />'
        "</head></html>"
    )
    result = await run(make_ctx, cache, body=body)
    assert ("eol_software", "drupal", "high") in kinds(result)


@respx.mock
async def test_no_banner_no_findings(make_ctx, cache):
    result = await run(make_ctx, cache, headers={"Server": "cloudflare"})
    assert result.findings == []
    assert result.coverage[0].status == "executed"


@respx.mock
async def test_vpn_appliance_detected(make_ctx, cache):
    page = (
        "<html><title>Please Login</title><script src='/remote/fgt_lang?lang=en'></script></html>"
    )
    result = await run(make_ctx, cache, routes={"remote/login": httpx.Response(200, text=page)})
    vpn = next(f for f in result.findings if f.evidence["kind"] == "vpn_appliance")
    assert vpn.evidence["vendor"] == "Fortinet"
    assert vpn.ipa_items == ["P2-1", "P1-4"]
    assert vpn.severity.value == "medium"
    assert vpn.evidence["kev_cves"] == ["CVE-2024-21762"]


@respx.mock
async def test_catch_all_200_does_not_fake_vpn(make_ctx, cache):
    result = await run(make_ctx, cache, fallback=httpx.Response(200, text="<html>shop</html>"))
    assert not any(f.evidence["kind"] == "vpn_appliance" for f in result.findings)


@respx.mock
async def test_probe_paths_are_get_only(make_ctx, cache):
    await run(make_ctx, cache)
    paths = {str(c.request.url) for c in respx.calls}
    assert {c.request.method for c in respx.calls} == {"GET"}
    assert {URL + p.path for p in VPN_PROBES} <= paths
