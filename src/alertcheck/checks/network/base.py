"""Shared plumbing for HTTP-based network checks."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx

from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation, redact_url

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
    endpoint = _endpoint(url)
    if endpoint[0] == "https" and endpoint not in ctx.tls_trust:
        async with ctx.tls_locks.setdefault(endpoint, asyncio.Lock()):
            if endpoint not in ctx.tls_trust:
                try:
                    return await _verified(ctx, url, max_body, kwargs)
                except httpx.ConnectError as e:
                    if not _is_cert_error(e):
                        raise
                    # mark the endpoint that actually failed (a redirect may have moved on)
                    failed = _endpoint(str(e.request.url)) if _has_request(e) else endpoint
                    ctx.tls_trust[failed] = False
                    if failed != endpoint:
                        raise
    if ctx.tls_trust.get(endpoint, True):
        return await _verified(ctx, url, max_body, kwargs)
    response = await ctx.http_unverified.get(url, max_body=max_body, **kwargs)
    response.extensions["alertcheck_unverified"] = True
    return response


async def _verified(
    ctx: Context, url: str, max_body: int, kwargs: dict[str, Any]
) -> httpx.Response:
    response = await ctx.http.get(url, max_body=max_body, **kwargs)
    ctx.tls_trust.setdefault(_endpoint(url), True)
    response.extensions["alertcheck_unverified"] = False
    return response


def _endpoint(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return (parts.scheme, (parts.hostname or "").lower(), port)


def _has_request(exc: httpx.HTTPError) -> bool:
    try:
        exc.request  # noqa: B018 - raises RuntimeError when unset
    except RuntimeError:
        return False
    return True


def probe_base(url: str) -> str:
    """Directory URL that relative probe paths resolve against (no query or fragment)."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


@dataclass
class InspectResult:
    """Findings plus how many sub-requests were attempted and failed."""

    findings: list[Finding]
    probes: int = 0
    failed: int = 0


# above this share of failed probes a target's result is not trustworthy
_MAX_FAILED_RATIO = 0.1


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
            result = await self.inspect(ctx, effective, response)
            artifacts = self.artifacts(effective, response)
        except (ScopeViolation, httpx.HTTPError) as e:
            detail = f"{type(e).__name__}: {e}"
            return (
                [],
                Coverage(check_id=self.id, target=target.url, status="error", detail=detail),
                {},
            )
        if isinstance(result, list):
            result = InspectResult(findings=result)
        notes = [f"via {effective.url}"] if effective.url != target.url else []
        status: Literal["executed", "error"] = "executed"
        if result.failed:
            notes.append(f"{result.failed}/{result.probes} probes failed")
            if result.failed > result.probes * _MAX_FAILED_RATIO:
                status = "error"
        coverage = Coverage(
            check_id=self.id, target=target.url, status=status, detail="; ".join(notes)
        )
        return result.findings, coverage, artifacts

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> list[Finding] | InspectResult:
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
            # targets end up in reports; never keep secrets from a URL there
            target=redact_url(target) if "://" in target else target,
            ipa_items=ipa_items,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence={"kind": kind, **(evidence or {})},
            references=references or [],
        )
