"""tls: protocol versions, ciphers, certificate and HTTPS redirect (design §7.3, IPA A-6 / D-4)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit

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

    def _endpoints(self, ctx: Context) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for t in http_targets(ctx):
            parts = urlsplit(t.url)
            if parts.scheme != "https" or not parts.hostname:
                continue
            endpoint = (parts.hostname, parts.port or 443)
            if endpoint not in out:
                out.append(endpoint)
        return out

    def plan(self, ctx: Context) -> list[Coverage]:
        endpoints = self._endpoints(ctx)
        if not endpoints:
            return [
                Coverage(
                    check_id=self.id,
                    target="*",
                    status="skipped_no_input",
                    detail="no HTTPS targets",
                )
            ]
        return [
            Coverage(check_id=self.id, target=f"{h}:{p}", status="executed") for h, p in endpoints
        ]

    async def run(self, ctx: Context) -> CheckResult:
        results = await asyncio.gather(
            *(self._endpoint(ctx, h, p) for h, p in self._endpoints(ctx))
        )
        merged = CheckResult()
        for findings, coverage in results:
            merged.findings += findings
            merged.coverage.append(coverage)
        return merged

    async def _endpoint(self, ctx: Context, host: str, port: int) -> tuple[list[Finding], Coverage]:
        target = f"{host}:{port}"
        decision = await ctx.guard.validate_resolution(host)
        address = ctx.guard.pinned_address(host) if decision.allowed else None
        if address is None:
            reason = decision.reason or "no validated address"
            return [], Coverage(check_id=self.id, target=target, status="error", detail=reason)

        ctx.audit({"event": "tls_scan", "host": host, "port": port, "address": address})
        if self._scanner is not None:
            scan = await asyncio.to_thread(self._scanner, host, port, address)
        else:
            concurrency = ctx.scope.limits.concurrency
            scan = await asyncio.to_thread(
                lambda: sslyze_scan.scan(host, port, address, concurrency=concurrency)
            )
        http_final = await self._http_final_url(ctx, host) if port == 443 else None

        if scan.error:
            if http_final is not None:
                f = self._finding(
                    "https_unavailable",
                    target,
                    Severity.high,
                    ["D-4"],
                    "HTTPS で接続できない（HTTP のみで提供している）",
                    "通信が暗号化されず、入力内容や Cookie を盗聴・改ざんされうる。",
                    "TLS 証明書を導入して HTTPS で提供し、HTTP は HTTPS へリダイレクトする。",
                    error=scan.error[:300],
                )
                return [f], Coverage(check_id=self.id, target=target, status="executed")
            return [], Coverage(
                check_id=self.id, target=target, status="error", detail=scan.error[:300]
            )

        findings = self._judge(scan, target)
        if http_final is not None and not http_final.startswith("https://"):
            findings.append(
                self._finding(
                    "no_https_redirect",
                    target,
                    Severity.medium,
                    ["D-4"],
                    "HTTP でのアクセスが HTTPS へ誘導されない",
                    "http:// で開いた利用者は暗号化されないまま通信を続けることになる。",
                    "HTTP へのアクセスを 301 で HTTPS へリダイレクトし、HSTS を設定する。",
                    final_url=http_final,
                )
            )
        return findings, Coverage(check_id=self.id, target=target, status="executed")

    async def _http_final_url(self, ctx: Context, host: str) -> str | None:
        """Final URL reached from http://host/, or None if plain HTTP is not served."""
        url = f"http://[{host}]/" if ":" in host else f"http://{host}/"
        try:
            response = await ctx.http.get(url, max_body=16 * 1024)
        except (httpx.HTTPError, ScopeViolation):
            return None
        return str(response.url)

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
