import json

import httpx
import respx

from alertcheck.checks.network.api import ApiCheck

URL = "https://www.example.co.jp/"
NF = httpx.Response(404, text="nf")


async def run(make_ctx, tmp_path, routes=None, endpoints=None, base_headers=None, fallback=NF):
    scope = {}
    if endpoints is not None:
        (tmp_path / "api.txt").write_text(endpoints, encoding="utf-8")
        scope["api_endpoints"] = "api.txt"
    ctx = make_ctx(targets={"urls": [URL]}, **scope)
    respx.get(URL).mock(
        side_effect=lambda req: httpx.Response(
            200,
            text="<html></html>",
            headers=(base_headers(req) if callable(base_headers) else base_headers or {}),
        )
    )
    for (method, path), resp in (routes or {}).items():
        respx.route(method=method, url=URL + path).mock(return_value=resp)
    respx.route().mock(return_value=fallback)
    result = await ApiCheck().run(ctx)
    await ctx.aclose()
    return result


def kinds(result):
    return {(f.evidence["kind"], f.severity.value) for f in result.findings}


@respx.mock
async def test_nothing_exposed(make_ctx, tmp_path):
    result = await run(make_ctx, tmp_path)
    assert result.findings == []


@respx.mock
async def test_openapi_document(make_ctx, tmp_path):
    doc = {"openapi": "3.0.0", "info": {"title": "x"}, "paths": {"/users": {}, "/orders": {}}}
    result = await run(
        make_ctx, tmp_path, routes={("GET", "swagger.json"): httpx.Response(200, json=doc)}
    )
    spec = next(f for f in result.findings if f.evidence["kind"] == "api_spec")
    assert spec.severity.value == "medium" and spec.ipa_items == ["A-4"]
    assert spec.evidence["paths"] == 2


@respx.mock
async def test_spec_path_returning_html_is_ignored(make_ctx, tmp_path):
    result = await run(make_ctx, tmp_path, fallback=httpx.Response(200, text="<html>shop</html>"))
    assert result.findings == []


@respx.mock
async def test_graphql_introspection_uses_only_schema_query(make_ctx, tmp_path):
    seen = []

    def graphql(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"data": {"__schema": {"types": [{"name": "User"}]}}})

    ctx_routes = {("POST", "graphql"): None}
    ctx = make_ctx(targets={"urls": [URL]})
    respx.get(URL).mock(return_value=httpx.Response(200))
    respx.post(URL + "graphql").mock(side_effect=graphql)
    respx.route().mock(return_value=NF)
    result = await ApiCheck().run(ctx)
    await ctx.aclose()
    assert ("graphql_introspection", "medium") in kinds(result)
    assert seen == [{"query": "{__schema{types{name}}}"}]
    assert ctx_routes


@respx.mock
async def test_unauthenticated_pii_is_critical(make_ctx, tmp_path):
    body = {"items": [{"id": 1, "Email": "a@example.co.jp", "name": "x"}]}
    result = await run(
        make_ctx,
        tmp_path,
        routes={("GET", "api/users"): httpx.Response(200, json=body)},
        endpoints="# comment\n/api/users\n",
    )
    pii = next(f for f in result.findings if f.evidence["kind"] == "unauthenticated_pii")
    assert pii.severity.value == "critical"
    assert pii.evidence["keys"] == ["Email"]
    assert "a@example.co.jp" not in json.dumps(pii.evidence)


@respx.mock
async def test_unauthenticated_json_without_pii_is_low(make_ctx, tmp_path):
    result = await run(
        make_ctx,
        tmp_path,
        routes={("GET", "api/status"): httpx.Response(200, json={"ok": True})},
        endpoints="/api/status\n",
    )
    assert ("unauthenticated_api", "low") in kinds(result)


@respx.mock
async def test_protected_endpoint_is_fine(make_ctx, tmp_path):
    result = await run(
        make_ctx,
        tmp_path,
        routes={("GET", "api/users"): httpx.Response(401, json={"error": "auth"})},
        endpoints="/api/users\n",
    )
    assert result.findings == []


@respx.mock
async def test_out_of_scope_endpoint_is_never_requested(make_ctx, tmp_path):
    evil = respx.get("https://evil.test/api").mock(
        return_value=httpx.Response(200, json={"email": "x"})
    )
    await run(make_ctx, tmp_path, endpoints="https://evil.test/api\n")
    assert not evil.called


@respx.mock
async def test_cors_reflection_with_credentials_is_high(make_ctx, tmp_path):
    def headers(req):
        origin = req.headers.get("origin")
        return (
            {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
            if origin
            else {}
        )

    result = await run(make_ctx, tmp_path, base_headers=headers)
    assert ("cors_reflection", "high") in kinds(result)


@respx.mock
async def test_cors_wildcard_is_not_reflection(make_ctx, tmp_path):
    result = await run(make_ctx, tmp_path, base_headers={"Access-Control-Allow-Origin": "*"})
    assert not any(f.evidence["kind"] == "cors_reflection" for f in result.findings)
