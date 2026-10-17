"""Shared plumbing for HTTP-based network checks."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit

import httpx

from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation

DEFAULT_MAX_BODY = 512 * 1024


@dataclass(frozen=True)
class HttpTarget:
    url: str
    # targets derived from a bare domain/IP may only speak plain HTTP
    http_fallback: bool = False


def _host_url(host: str) -> str:
    return f"https://[{host}]/" if ":" in host else f"https://{host}/"


def http_targets(ctx: Context) -> list[HttpTarget]:
    """Base URLs to inspect: explicit URLs, then domains, hosts and discovered hosts."""
    targets = ctx.scope.targets
    candidates = [HttpTarget(u) for u in targets.urls]
    auto_hosts = list(targets.domains) + list(targets.hosts)
    auto_hosts += ctx.artifacts.get("discovery", {}).get("hosts", [])
    candidates += [HttpTarget(_host_url(h), http_fallback=True) for h in auto_hosts]

    seen: set[str] = set()
    out = []
    for t in candidates:
        if t.url in seen or not ctx.guard.check_url(t.url).allowed:
            continue
        seen.add(t.url)
        out.append(t)
    return out


def _is_cert_error(exc: BaseException) -> bool:
    seen = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        if "CERTIFICATE_VERIFY_FAILED" in str(current):
            return True
        current = current.__cause__ or current.__context__
    return False


async def fetch(
    ctx: Context, url: str, *, max_body: int = DEFAULT_MAX_BODY, **kwargs: Any
) -> httpx.Response:
    """GET through the scope guard; retry without verification on certificate errors.

    Certificate problems are reported by the tls check, so other checks still
    inspect the site. The unverified client never carries credentials.
    """
    host = urlsplit(url).hostname or ""
    if host not in ctx.untrusted_tls_hosts:
        try:
            response = await ctx.http.get(url, max_body=max_body, **kwargs)
            response.extensions["alertcheck_unverified"] = False
            return response
        except httpx.ConnectError as e:
            if not _is_cert_error(e):
                raise
        ctx.untrusted_tls_hosts.add(host)
    response = await ctx.http_unverified.get(url, max_body=max_body, **kwargs)
    response.extensions["alertcheck_unverified"] = True
    return response


class HttpCheck:
    """Runs ``inspect`` once per HTTP target with per-target error isolation."""

    id: ClassVar[str]
    ipa_items: ClassVar[list[str]]
    group: ClassVar[Literal["network"]] = "network"
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def plan(self, ctx: Context) -> list[Coverage]:
        targets = http_targets(ctx)
        if not targets:
            return [
                Coverage(
                    check_id=self.id,
                    target="*",
                    status="skipped_no_input",
                    detail="no HTTP targets",
                )
            ]
        return [Coverage(check_id=self.id, target=t.url, status="executed") for t in targets]

    async def run(self, ctx: Context) -> CheckResult:
        targets = http_targets(ctx)
        results = await asyncio.gather(*(self._run_target(ctx, t) for t in targets))
        merged = CheckResult()
        for findings, coverage, artifacts in results:
            merged.findings += findings
            merged.coverage.append(coverage)
            for key, value in artifacts.items():
                merged.artifacts.setdefault(key, {}).update(value)
        return merged

    async def _base_response(
        self, ctx: Context, target: HttpTarget
    ) -> tuple[HttpTarget, httpx.Response]:
        try:
            return target, await fetch(ctx, target.url)
        except httpx.ConnectError:
            if not target.http_fallback:
                raise
        plain = HttpTarget("http://" + target.url.removeprefix("https://"))
        return plain, await fetch(ctx, plain.url)

    async def _run_target(
        self, ctx: Context, target: HttpTarget
    ) -> tuple[list[Finding], Coverage, dict[str, dict[str, Any]]]:
        artifacts: dict[str, dict[str, Any]] = {}
        try:
            effective, response = await self._base_response(ctx, target)
            findings = await self.inspect(ctx, effective, response)
            artifacts = self.artifacts(effective, response)
        except (ScopeViolation, httpx.HTTPError) as e:
            detail = f"{type(e).__name__}: {e}"
            return (
                [],
                Coverage(check_id=self.id, target=target.url, status="error", detail=detail),
                {},
            )
        detail = f"via {effective.url}" if effective.url != target.url else ""
        coverage = Coverage(check_id=self.id, target=target.url, status="executed", detail=detail)
        return findings, coverage, artifacts

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> list[Finding]:
        raise NotImplementedError

    def artifacts(self, target: HttpTarget, response: httpx.Response) -> dict[str, dict[str, Any]]:
        """Data to share with later checks, keyed by artifact name then target URL."""
        return {}

    def finding(
        self,
        *,
        kind: str,
        target: str,
        severity: Severity,
        ipa_items: list[str],
        title: str,
        description: str,
        remediation: str,
        evidence: dict[str, Any] | None = None,
        references: list[str] | None = None,
        variant: str = "",
    ) -> Finding:
        """Build a Finding; ``variant`` separates IDs of same-kind findings on one target."""
        return Finding.create(
            check_id=self.id,
            kind=f"{kind}:{variant}" if variant else kind,
            target=target,
            ipa_items=ipa_items,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence={"kind": kind, **(evidence or {})},
            references=references or [],
        )
