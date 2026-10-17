"""tls: protocol versions, ciphers, certificate and HTTPS redirect (design §7.3, IPA A-6 / D-4)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, Literal
from urllib.parse import urljoin, urlsplit

import httpx

from alertcheck.adapters import sslyze_scan
from alertcheck.adapters.sslyze_scan import TlsScanResult
from alertcheck.checks.network.base import http_targets
from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation

_IPA = ["A-6", "D-4"]
_EXPIRY_WARNING = timedelta(days=30)
_REF = "https://www.ipa.go.jp/security/crypto/guideline/ssl_crypt_config.html"

Scanner = Callable[[str, int, str], TlsScanResult]


class TlsCheck:
    id: ClassVar[str] = "tls"
    group: ClassVar[Literal["network"]] = "network"
    ipa_items: ClassVar[list[str]] = _IPA
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(
        self, scanner: Scanner | None = None, now: Callable[[], datetime] | None = None
    ) -> None:
        self._scanner = scanner
        self._now = now or (lambda: datetime.now(UTC))

    def _targets(self, ctx: Context) -> tuple[list[tuple[str, int]], list[str], list[str]]:
        """(HTTPS endpoints to scan, plain-HTTP URLs to check, URL-prefix-only endpoints)."""
        endpoints: list[tuple[str, int]] = []
        prefix_only: list[str] = []
        http_urls: list[str] = []
        for t in http_targets(ctx):
            parts = urlsplit(t.url)
            if not parts.hostname:
                continue
            if parts.scheme == "http":
                if t.url not in http_urls:
                    http_urls.append(t.url)
                continue
            endpoint = (parts.hostname, parts.port or 443)
            label = f"{endpoint[0]}:{endpoint[1]}"
            # a URL prefix authorizes its path; a full TLS scan needs host-wide authorization
            if not ctx.guard.check_host(parts.hostname).allowed:
                if label not in prefix_only:
                    prefix_only.append(label)
                continue
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        return endpoints, http_urls, prefix_only

    def plan(self, ctx: Context) -> list[Coverage]:
        endpoints, http_urls, prefix_only = self._targets(ctx)
        coverage = [
            Coverage(check_id=self.id, target=f"{h}:{p}", status="executed") for h, p in endpoints
        ]
        coverage += [Coverage(check_id=self.id, target=u, status="executed") for u in http_urls]
        coverage += [self._prefix_skip(label) for label in prefix_only]
        if not coverage:
            return [
                Coverage(
                    check_id=self.id, target="*", status="skipped_no_input", detail="no targets"
                )
            ]
        return coverage

    def _prefix_skip(self, label: str) -> Coverage:
        return Coverage(
            check_id=self.id,
            target=label,
            status="skipped_by_option",
            detail="URL-prefix target only; add a domain/IP target to authorize a TLS scan",
        )

    async def run(self, ctx: Context) -> CheckResult:
        endpoints, http_urls, prefix_only = self._targets(ctx)
        # one sslyze scan at a time keeps total connections within limits.concurrency
        gate = asyncio.Semaphore(1)
        tasks = [self._safe_endpoint(ctx, h, p, gate) for h, p in endpoints]
        tasks += [self._safe_http_target(ctx, u) for u in http_urls]
        results = await asyncio.gather(*tasks)
        merged = CheckResult()
        for findings, coverage in results:
            merged.findings += findings
            merged.coverage.append(coverage)
        merged.coverage += [self._prefix_skip(label) for label in prefix_only]
        return merged

    async def _safe_endpoint(
        self, ctx: Context, host: str, port: int, gate: asyncio.Semaphore
    ) -> tuple[list[Finding], Coverage]:
        try:
            return await self._endpoint(ctx, host, port, gate)
        except Exception as e:  # one endpoint must not stop the others
            detail = f"{type(e).__name__}: {e}"[:300]
            return [], Coverage(
                check_id=self.id, target=f"{host}:{port}", status="error", detail=detail
            )

    async def _safe_http_target(self, ctx: Context, url: str) -> tuple[list[Finding], Coverage]:
        try:
            probe = await self._http_probe(ctx, url)
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"[:300]
            return [], Coverage(check_id=self.id, target=url, status="error", detail=detail)
        if probe is None:
            return [], Coverage(
                check_id=self.id, target=url, status="error", detail="HTTP not reachable"
            )
        findings = [] if probe else [self._no_redirect(url, url)]
        return findings, Coverage(check_id=self.id, target=url, status="executed")

    async def _endpoint(
        self, ctx: Context, host: str, port: int, gate: asyncio.Semaphore
    ) -> tuple[list[Finding], Coverage]:
        target = f"{host}:{port}"
        decision = await ctx.guard.validate_resolution(host)
        address = ctx.guard.pinned_address(host) if decision.allowed else None
        if address is None:
            reason = decision.reason or "no validated address"
            return [], Coverage(check_id=self.id, target=target, status="error", detail=reason)

        async with gate:
            ctx.audit({"event": "tls_scan", "host": host, "port": port, "address": address})
            if self._scanner is not None:
                scan = await asyncio.to_thread(self._scanner, host, port, address)
            else:
                concurrency = ctx.scope.limits.concurrency
                scan = await asyncio.to_thread(
                    lambda: sslyze_scan.scan(host, port, address, concurrency=concurrency)
                )
        redirects = None
        if port == 443:
            host_url = f"http://[{host}]/" if ":" in host else f"http://{host}/"
            redirects = await self._http_probe(ctx, host_url)

        if scan.error:
            if redirects is not None:
                f = self._finding(
                    "https_unavailable",
                    target,
                    Severity.high,
                    ["D-4"],
                    "HTTPS で接続できない"
                    + (
                        "（HTTP は HTTPS へ誘導しているが接続先が応答しない）"
                        if redirects
                        else "（HTTP のみで提供している）"
                    ),
                    "通信が暗号化されず、入力内容や Cookie を盗聴・改ざんされうる。",
                    "TLS 証明書を導入して HTTPS で提供し、HTTP は HTTPS へリダイレクトする。",
                    error=scan.error[:300],
                    http_redirects_to_https=redirects,
                )
                return [f], Coverage(check_id=self.id, target=target, status="executed")
            return [], Coverage(
                check_id=self.id, target=target, status="error", detail=scan.error[:300]
            )

        findings = self._judge(scan, target)
        if redirects is False:
            findings.append(self._no_redirect(target, f"http://{host}/"))
        return findings, Coverage(check_id=self.id, target=target, status="executed")

    async def _http_probe(self, ctx: Context, url: str) -> bool | None:
        """Whether plain HTTP redirects to HTTPS; None if plain HTTP is not served.

        Only the first response is inspected, so a redirect to a dead HTTPS
        endpoint still counts as "served".
        """
        try:
            response = await ctx.http.get(url, max_body=16 * 1024, redirects=0)
        except (httpx.HTTPError, ScopeViolation):
            return None
        location = response.headers.get("location", "")
        return response.is_redirect and urljoin(url, location).startswith("https://")

    def _no_redirect(self, target: str, url: str) -> Finding:
        return self._finding(
            "no_https_redirect",
            target,
            Severity.medium,
            ["D-4"],
            "HTTP でのアクセスが HTTPS へ誘導されない",
            "http:// で開いた利用者は暗号化されないまま通信を続けることになる。",
            "HTTP へのアクセスを 301 で HTTPS へリダイレクトし、HSTS を設定する。",
            url=url,
        )

    def _judge(self, scan: TlsScanResult, target: str) -> list[Finding]:
        out: list[Finding] = []
        ssl_versions = sorted(scan.accepted_protocols & {"SSLv2", "SSLv3"})
        if ssl_versions:
            out.append(
                self._finding(
                    "legacy_ssl",
                    target,
                    Severity.high,
                    _IPA,
                    f"SSL（{', '.join(ssl_versions)}）が有効になっている",
                    "既知の攻撃（POODLE など）で通信内容を解読されうる。",
                    "SSLv2 / SSLv3 を無効化し、TLS 1.2 以上のみを許可する。",
                    protocols=ssl_versions,
                )
            )
        legacy = sorted(scan.accepted_protocols & {"TLSv1.0", "TLSv1.1"})
        if legacy:
            out.append(
                self._finding(
                    "legacy_tls",
                    target,
                    Severity.medium,
                    _IPA,
                    f"古い TLS（{', '.join(legacy)}）が有効になっている",
                    "TLS 1.0 / 1.1 は既に非推奨で、弱い暗号の利用を許すことになる。",
                    "TLS 1.0 / 1.1 を無効化し、TLS 1.2 以上のみを許可する。",
                    protocols=legacy,
                )
            )
        if scan.weak_ciphers:
            out.append(
                self._finding(
                    "weak_cipher",
                    target,
                    Severity.medium,
                    _IPA,
                    "弱い暗号スイートが有効になっている",
                    "RC4・3DES・NULL・EXPORT などの暗号は解読や改ざんのリスクがある。",
                    "IPA の TLS 暗号設定ガイドラインに沿って暗号スイートを絞り込む。",
                    ciphers=scan.weak_ciphers[:20],
                )
            )
        if scan.cert_not_after is not None:
            remaining = scan.cert_not_after - self._now()
            expiry = scan.cert_not_after.isoformat()
            if remaining <= timedelta(0):
                out.append(
                    self._finding(
                        "cert_expired",
                        target,
                        Severity.high,
                        _IPA,
                        "TLS 証明書の有効期限が切れている",
                        "ブラウザが警告を出し、利用者が警告を無視する習慣を生む。",
                        "証明書を更新し、自動更新の仕組みを整える。",
                        not_after=expiry,
                    )
                )
            elif remaining <= _EXPIRY_WARNING:
                out.append(
                    self._finding(
                        "cert_expiring",
                        target,
                        Severity.medium,
                        _IPA,
                        f"TLS 証明書の有効期限が近い（残り {remaining.days} 日）",
                        "期限切れになるとサービスが利用できなくなる。",
                        "証明書を更新し、自動更新の仕組みを整える。",
                        not_after=expiry,
                    )
                )
        if scan.hostname_matches is False:
            out.append(
                self._finding(
                    "cert_hostname_mismatch",
                    target,
                    Severity.high,
                    _IPA,
                    "TLS 証明書のホスト名が一致しない",
                    "ブラウザが警告を出し、なりすましと区別できなくなる。",
                    "このホスト名を含む証明書を設定する。",
                )
            )
        elif scan.trusted is False:
            out.append(
                self._finding(
                    "cert_untrusted",
                    target,
                    Severity.medium,
                    _IPA,
                    "TLS 証明書が信頼されていない（自己署名・中間証明書の不足など）",
                    "ブラウザが警告を出し、なりすましと区別できなくなる。",
                    "公的な認証局の証明書を使い、中間証明書を含めて設定する。",
                )
            )
        return out

    def _finding(
        self,
        kind: str,
        target: str,
        severity: Severity,
        ipa_items: list[str],
        title: str,
        description: str,
        remediation: str,
        **evidence: Any,
    ) -> Finding:
        return Finding.create(
            check_id=self.id,
            kind=kind,
            target=target,
            ipa_items=ipa_items,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence={"kind": kind, **evidence},
            references=[_REF],
        )
