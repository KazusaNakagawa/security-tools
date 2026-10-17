"""http.headers: security headers and version disclosure (design §7.3, IPA A-6)."""

from __future__ import annotations

import re
from typing import Any

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity

_VERSION = re.compile(r"\d+\.\d+")
_MAX_AGE_VALUE = re.compile(r'(\d+)|"(\d+)"')


def hsts_max_age(value: str) -> int | None:
    """max-age of a Strict-Transport-Security value, or None if absent or malformed."""
    for directive in value.split(";"):
        name, _, raw = directive.partition("=")
        if name.strip().lower() != "max-age":
            continue
        match = _MAX_AGE_VALUE.fullmatch(raw.strip())
        return int(match.group(1) or match.group(2)) if match else None
    return None


def has_frame_ancestors(csp: str) -> bool:
    """True only for a real frame-ancestors directive with at least one source."""
    for directive in csp.split(";"):
        tokens = directive.split()
        if tokens and tokens[0].lower() == "frame-ancestors" and len(tokens) > 1:
            return True
    return False


def valid_x_frame_options(value: str) -> bool:
    # ALLOW-FROM is ignored by current browsers, so it gives no protection
    return value.strip().lower() in ("deny", "sameorigin")


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

        if url.startswith("https://") and not hsts_max_age(h.get("strict-transport-security", "")):
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
        framed = bool(csp) and has_frame_ancestors(csp)
        if not framed and not valid_x_frame_options(h.get("x-frame-options", "")):
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
