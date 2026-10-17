"""http.headers: security headers and version disclosure (design §7.3, IPA A-6)."""

from __future__ import annotations

import re
from typing import Any

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity

_VERSION = re.compile(r"\d+\.\d+")
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
_IPA = ["A-6"]
_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


class HttpHeadersCheck(HttpCheck):
    id = "http.headers"
    ipa_items = _IPA

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> list[Finding]:
        url = str(response.url)
        h = response.headers
        findings: list[Finding] = []

        def add(
            kind: str,
            severity: Severity,
            title: str,
            description: str,
            remediation: str,
            variant: str = "",
            **evidence: Any,
        ) -> None:
            findings.append(
                self.finding(
                    kind=kind,
                    variant=variant,
                    target=url,
                    severity=severity,
                    ipa_items=_IPA,
                    title=title,
                    description=description,
                    remediation=remediation,
                    evidence=evidence,
                    references=[_OWASP_HEADERS],
                )
            )

        if url.startswith("https://"):
            match = _MAX_AGE.search(h.get("strict-transport-security", ""))
            if not match or int(match.group(1)) == 0:
                add(
                    "hsts_missing",
                    Severity.medium,
                    "HSTS が設定されていない",
                    "Strict-Transport-Security がないため、初回アクセスや中間者攻撃で HTTP に格下げされうる。",
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains を付与する。",
                    value=h.get("strict-transport-security"),
                )

        csp = h.get("content-security-policy")
        if not csp:
            add(
                "csp_missing",
                Severity.medium,
                "Content-Security-Policy が設定されていない",
                "CSP がないため、XSS が成立した場合の被害を抑えられない。",
                "Content-Security-Policy を設定する（まず default-src 'self' から始める）。",
            )
        has_frame_ancestors = bool(csp) and "frame-ancestors" in csp.lower()
        if not has_frame_ancestors and not h.get("x-frame-options"):
            add(
                "clickjacking",
                Severity.medium,
                "クリックジャッキング対策がない",
                "CSP の frame-ancestors も X-Frame-Options もないため、他サイトに埋め込まれて操作を誘導されうる。",
                "Content-Security-Policy: frame-ancestors 'self'（または X-Frame-Options: DENY）を付与する。",
            )
        if h.get("x-content-type-options", "").strip().lower() != "nosniff":
            add(
                "nosniff_missing",
                Severity.low,
                "X-Content-Type-Options: nosniff が設定されていない",
                "ブラウザが Content-Type を推測し、意図しない形式で解釈する余地がある。",
                "X-Content-Type-Options: nosniff を付与する。",
            )
        if not h.get("referrer-policy"):
            add(
                "referrer_policy_missing",
                Severity.low,
                "Referrer-Policy が設定されていない",
                "URL に含まれる情報が外部サイトへ Referer として送られうる。",
                "Referrer-Policy: strict-origin-when-cross-origin を付与する。",
            )
        if not h.get("permissions-policy"):
            add(
                "permissions_policy_missing",
                Severity.info,
                "Permissions-Policy が設定されていない",
                "カメラや位置情報などブラウザ機能の利用範囲を制限していない。",
                "不要な機能を Permissions-Policy で無効化する。",
            )
        for header in ("server", "x-powered-by"):
            value = h.get(header)
            if value and _VERSION.search(value):
                add(
                    "version_disclosure",
                    Severity.low,
                    f"{header} ヘッダでソフトウェアのバージョンを公開している",
                    f"{header}: {value} から製品とバージョンが分かり、既知の脆弱性を狙われやすくなる。",
                    "バージョン表示を無効化する（例: nginx の server_tokens off、PHP の expose_php Off）。",
                    variant=header,
                    header=header,
                    value=value,
                )
        return findings

    def artifacts(self, target: HttpTarget, response: httpx.Response) -> dict[str, dict[str, Any]]:
        h = response.headers
        return {
            "banners": {
                target.url: {"server": h.get("server"), "x_powered_by": h.get("x-powered-by")}
            }
        }
