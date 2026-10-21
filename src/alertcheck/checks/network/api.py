"""api: exposed API specs, GraphQL introspection, unauthenticated data, CORS (IPA A-4).

Design §7.3. Only safe probes: GETs for known spec paths and the configured
endpoints (no auth header), a single GraphQL introspection query, and a CORS
preflight-style GET with a fabricated Origin. No parameters are fuzzed.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget, InspectResult, fetch
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation

_IPA = ["A-4"]
SPEC_PATHS = [
    "swagger.json",
    "openapi.json",
    "v3/api-docs",
    "api-docs",
    "swagger/v1/swagger.json",
    "swagger-ui/index.html",
    "api/swagger.json",
    ".well-known/openapi.json",
]
GRAPHQL_PATHS = ["graphql", "api/graphql", "v1/graphql", "query"]
INTROSPECTION = {"query": "{__schema{types{name}}}"}
EVIL_ORIGIN = "https://evil.invalid"
_PII_KEYS = re.compile(
    r"^(e?mail|tel|phone|mobile|address|addr|zip|postal|birth|dob|ssn|my_?number|"
    r"card|credit|passport|license|account_?no)$",
    re.IGNORECASE,
)
_FAILED = object()


def _looks_like_openapi(data: Any) -> bool:
    return isinstance(data, dict) and ("openapi" in data or "swagger" in data)


def _pii_keys(data: Any, found: set[str], depth: int = 0) -> set[str]:
    if depth > 6:
        return found
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(key, str) and _PII_KEYS.match(key) and not isinstance(value, dict | list):
                found.add(key)
            _pii_keys(value, found, depth + 1)
    elif isinstance(data, list):
        for item in data[:50]:
            _pii_keys(item, found, depth + 1)
    return found


class ApiCheck(HttpCheck):
    id = "api"
    ipa_items = _IPA

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> InspectResult:
        base = target.url if target.url.endswith("/") else target.url + "/"
        findings: list[Finding] = []
        failed = 0

        cors = self._cors(target.url, response)
        if cors:
            findings.append(cors)

        probes = [self._spec(ctx, base, p) for p in SPEC_PATHS]
        probes += [self._graphql(ctx, base, p) for p in GRAPHQL_PATHS]
        probes += [self._endpoint(ctx, url) for url in self._endpoint_urls(ctx)]
        for outcome in await asyncio.gather(*probes):
            if outcome is _FAILED:
                failed += 1
            elif isinstance(outcome, Finding):
                findings.append(outcome)
        return InspectResult(findings=findings, probes=len(probes), failed=failed)

    def _endpoint_urls(self, ctx: Context) -> list[str]:
        if not ctx.scope.api_endpoints:
            return []
        try:
            with ctx.infra.workspace.open_input(ctx.scope.api_endpoints) as f:
                lines = f.read().decode("utf-8-sig").splitlines()
        except (OSError, PermissionError, UnicodeDecodeError):
            return []
        urls = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = (
                line
                if "://" in line
                else urljoin(str(ctx.scope.targets.urls[0] if ctx.scope.targets.urls else ""), line)
            )
            if ctx.guard.check_url(url).allowed:
                urls.append(url)
        return urls

    async def _get(self, ctx: Context, url: str, **kwargs: Any) -> httpx.Response | object | None:
        try:
            return await fetch(ctx, url, max_body=256 * 1024, **kwargs)
        except ScopeViolation:
            return None
        except httpx.HTTPError:
            return _FAILED

    async def _spec(self, ctx: Context, base: str, path: str) -> Finding | object | None:
        url = urljoin(base, path)
        resp = await self._get(ctx, url)
        if not isinstance(resp, httpx.Response) or resp.status_code != 200:
            return resp if resp is _FAILED else None
        ctype = resp.headers.get("content-type", "")
        is_spec = False
        if "json" in ctype or path.endswith(".json"):
            try:
                is_spec = _looks_like_openapi(resp.json())
                paths = len((resp.json() or {}).get("paths", {})) if is_spec else 0
            except ValueError:
                return None
        elif "swagger-ui" in path and "swagger" in resp.text.lower():
            is_spec, paths = True, 0
        else:
            return None
        if not is_spec:
            return None
        return self.finding(
            kind="api_spec",
            variant=path,
            target=url,
            severity=Severity.medium,
            ipa_items=_IPA,
            title="API 仕様書が公開されている",
            description="全エンドポイントとパラメータが分かり、攻撃対象の把握を容易にする。",
            remediation="本番環境では API 仕様の公開を停止するか、認証の背後に置く。",
            evidence={"path": path, "url": url, "paths": paths},
        )

    async def _graphql(self, ctx: Context, base: str, path: str) -> Finding | object | None:
        url = urljoin(base, path)
        resp = await self._get(
            ctx,
            url,
            method="POST",
            json=INTROSPECTION,
            headers={"Content-Type": "application/json"},
        )
        if not isinstance(resp, httpx.Response) or resp.status_code != 200:
            return resp if resp is _FAILED else None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not (isinstance(data, dict) and (data.get("data") or {}).get("__schema")):
            return None
        return self.finding(
            kind="graphql_introspection",
            variant=path,
            target=url,
            severity=Severity.medium,
            ipa_items=_IPA,
            title="GraphQL のイントロスペクションが有効になっている",
            description="スキーマ全体を取得でき、内部のデータ構造や未公開の操作が分かる。",
            remediation="本番環境ではイントロスペクションを無効にする。",
            evidence={"path": path, "url": url},
        )

    async def _endpoint(self, ctx: Context, url: str) -> Finding | object | None:
        resp = await self._get(ctx, url)
        if not isinstance(resp, httpx.Response) or resp.status_code != 200:
            return resp if resp is _FAILED else None
        if "json" not in resp.headers.get("content-type", ""):
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        pii = sorted(_pii_keys(data, set()))
        if pii:
            return self.finding(
                kind="unauthenticated_pii",
                variant=url,
                target=url,
                severity=Severity.critical,
                ipa_items=["A-4", "D-2"],
                title="認証なしで個人情報らしきデータを返す API がある",
                description="認証ヘッダを付けずに取得でき、応答に個人情報らしいキーが含まれる。情報漏えいに直結しうる。",
                remediation="API に認証・認可を導入し、認証なしのアクセスを拒否する。公開範囲も見直す。",
                evidence={"url": url, "keys": pii},
            )
        return self.finding(
            kind="unauthenticated_api",
            variant=url,
            target=url,
            severity=Severity.low,
            ipa_items=_IPA,
            title="認証なしで応答する API がある",
            description="認証ヘッダなしで 200 と JSON を返す。意図した公開かを確認する必要がある。",
            remediation="公開が意図したものか確認し、不要なら認証を必須にする。",
            evidence={"url": url},
        )

    def _cors(self, url: str, response: httpx.Response) -> Finding | None:
        # the base response is fetched without an Origin header, so a reflected
        # Origin here would require the server to echo an absent value; instead
        # treat an Origin-independent wildcard+credentials as the risky case.
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao and acao != "*" and acac and urlsplit(acao).hostname != urlsplit(url).hostname:
            return self.finding(
                kind="cors_reflection",
                variant="base",
                target=url,
                severity=Severity.high,
                ipa_items=_IPA,
                title="CORS が任意オリジンに資格情報付きでアクセスを許している",
                description="Access-Control-Allow-Origin がリクエスト元を反射し、Allow-Credentials も true のため、他サイトから Cookie 付きで API を呼ばれうる。",
                remediation="許可するオリジンを明示的なリストに限定し、資格情報付きで任意オリジンを許可しない。",
                evidence={"allow_origin": acao, "allow_credentials": acac},
            )
        return None

    async def _base_response(self, ctx: Context, target: HttpTarget):
        # send a fabricated Origin so CORS reflection shows up on the base response
        effective, _ = await super()._base_response(ctx, target)
        response = await fetch(ctx, effective.url, headers={"Origin": EVIL_ORIGIN})
        return effective, response
