"""http.cookies: Secure / HttpOnly / SameSite on session cookies (design §7.3, IPA A-2)."""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity

_IPA = ["A-2"]
_SESSION_LIKE = re.compile(r"sess|sid|token|auth|remember|jwt|login", re.IGNORECASE)
# CSRF tokens are read by client-side JavaScript on purpose, so HttpOnly is not expected
_JS_READABLE = re.compile(r"csrf|xsrf", re.IGNORECASE)
_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"


@dataclass(frozen=True)
class SetCookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    domain: str | None = None
    path: str | None = None


def parse_set_cookie(header: str) -> SetCookie | None:
    """Parse the attributes of one Set-Cookie header; the value is discarded."""
    first, *attrs = header.split(";")
    name = first.partition("=")[0].strip()
    if not name:
        return None
    flags: dict[str, str] = {}
    for attr in attrs:
        key, _, value = attr.partition("=")
        flags[key.strip().lower()] = value.strip().lower()
    return SetCookie(
        name=name,
        secure="secure" in flags,
        httponly="httponly" in flags,
        samesite=flags.get("samesite") or None,
        domain=flags.get("domain") or None,
        path=flags.get("path") or None,
    )


class HttpCookiesCheck(HttpCheck):
    id = "http.cookies"
    ipa_items = _IPA

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[SetCookie] = set()
        # judge every instance: a later Set-Cookie for the same name may be weaker or scoped
        # differently; only exact duplicates are skipped
        for resp in [*response.history, response]:
            url = str(resp.url)
            https = url.startswith("https://")
            for header in resp.headers.get_list("set-cookie"):
                cookie = parse_set_cookie(header)
                if cookie is None or cookie in seen or not _SESSION_LIKE.search(cookie.name):
                    continue
                seen.add(cookie)
                findings += self._judge(cookie, url, https)
        unique: dict[str, Finding] = {}
        for f in findings:
            unique.setdefault(f.id, f)
        return list(unique.values())

    def _judge(self, cookie: SetCookie, url: str, https: bool) -> list[Finding]:
        out = []

        def add(kind: str, severity: Severity, title: str, description: str, fix: str) -> None:
            out.append(
                self.finding(
                    kind=kind,
                    variant=f"{cookie.name}|{cookie.domain or ''}|{cookie.path or '/'}",
                    target=url,
                    severity=severity,
                    ipa_items=_IPA,
                    title=f"{title}（{cookie.name}）",
                    description=description,
                    remediation=fix,
                    evidence={
                        "cookie": cookie.name,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "over_http": not https,
                        "secure": cookie.secure,
                        "httponly": cookie.httponly,
                        "samesite": cookie.samesite,
                    },
                    references=[_REF],
                )
            )

        if not cookie.secure:
            add(
                "cookie_secure_missing",
                Severity.medium,
                "セッション Cookie に Secure 属性がない",
                (
                    "HTTP で発行されており、通信経路でセッションを盗聴されうる。"
                    if not https
                    else "HTTP 通信にも Cookie が送られ、盗聴でセッションを奪われうる。"
                ),
                "HTTPS で提供し、Set-Cookie に Secure を付与する。",
            )
        if not cookie.httponly and not _JS_READABLE.search(cookie.name):
            add(
                "cookie_httponly_missing",
                Severity.medium,
                "セッション Cookie に HttpOnly 属性がない",
                "XSS が成立した場合に JavaScript から Cookie を読み取られる。",
                "Set-Cookie に HttpOnly を付与する。",
            )
        if cookie.samesite is None:
            add(
                "cookie_samesite_missing",
                Severity.low,
                "セッション Cookie に SameSite 属性がない",
                "ブラウザの既定動作に依存しており、CSRF 対策として明示されていない。",
                "SameSite=Lax（または Strict）を付与する。",
            )
        elif cookie.samesite == "none" and not cookie.secure:
            add(
                "cookie_samesite_none_insecure",
                Severity.medium,
                "SameSite=None なのに Secure 属性がない",
                "主要ブラウザは Secure のない SameSite=None を拒否し、また他サイトからの送信を許す設定になっている。",
                "SameSite=None を使う場合は Secure を付与する。不要なら SameSite=Lax にする。",
            )
        return out
