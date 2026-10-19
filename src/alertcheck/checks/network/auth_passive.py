"""auth.passive: login forms sent over HTTP and MFA hints (IPA A-2).

Design §7.3. Only reads pages; never submits credentials. MFA presence is a
heuristic to be confirmed via the questionnaire, so its absence is info.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget, InspectResult, fetch
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation

_IPA = ["A-2"]
LOGIN_PATHS = ["login", "signin", "admin/login", "wp-login.php", "users/sign_in", "account/login"]
_PASSWORD_INPUT = re.compile(r"<input\b[^>]*type\s*=\s*[\"']?password", re.IGNORECASE)
_FORM = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ACTION = re.compile(r"action\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
_MFA_HINT = re.compile(
    r"多要素|二要素|二段階|ワンタイム|認証コード|mfa|2fa|two[- ]?factor|one[- ]?time|otp|totp|authenticator",
    re.IGNORECASE,
)


def login_form_action(html: str) -> str | None:
    """Action of the first form that contains a password field, '' if same page."""
    for match in _FORM.finditer(html):
        end = html.find("</form>", match.end())
        body = html[match.start() : end if end != -1 else len(html)]
        if _PASSWORD_INPUT.search(body):
            action = _ACTION.search(match.group(0))
            return action.group(1) if action else ""
    return None


class AuthPassiveCheck(HttpCheck):
    id = "auth.passive"
    ipa_items = _IPA

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> InspectResult:
        findings: list[Finding] = []
        login_urls: list[str] = []
        failed = 0
        seen: set[str] = set()

        pages = [(str(response.url), response)]
        base = target.url if target.url.endswith("/") else target.url + "/"
        for path in LOGIN_PATHS:
            url = urljoin(base, path)
            try:
                resp = await fetch(ctx, url, max_body=256 * 1024)
            except ScopeViolation:
                continue
            except httpx.HTTPError:
                failed += 1
                continue
            if resp.status_code == 200:
                pages.append((str(resp.url), resp))

        for url, resp in pages:
            if url in seen or urlsplit(url).scheme not in ("http", "https"):
                continue
            seen.add(url)
            action = login_form_action(resp.text)
            if action is None:
                continue
            login_urls.append(url)
            findings += self._judge(url, action, resp.text)

        result = InspectResult(findings=findings, probes=len(LOGIN_PATHS), failed=failed)
        if login_urls:
            result.findings = findings
        self._login_urls = login_urls
        return result

    def artifacts(self, target: HttpTarget, response: httpx.Response):
        urls = getattr(self, "_login_urls", [])
        return {"login_pages": {target.url: urls}} if urls else {}

    def _judge(self, url: str, action: str, html: str) -> list[Finding]:
        action_url = urljoin(url, action) if action else url
        over_http = action_url.startswith("http://")
        if over_http:
            return [
                self.finding(
                    kind="login_over_http",
                    variant=url,
                    target=url,
                    severity=Severity.high,
                    ipa_items=_IPA,
                    title="ログインフォームが暗号化されない経路で認証情報を送信する",
                    description="フォームの送信先が http:// のため、入力したユーザー名とパスワードを盗聴されうる。",
                    remediation="ログインは HTTPS で提供し、フォームの送信先も https:// にする。HTTP は HTTPS へリダイレクトする。",
                    evidence={"url": url, "form_action": action_url},
                )
            ]
        if not _MFA_HINT.search(html):
            return [
                self.finding(
                    kind="mfa_not_mentioned",
                    variant=url,
                    target=url,
                    severity=Severity.info,
                    ipa_items=_IPA,
                    title="ログイン画面に多要素認証の記載が見当たらない",
                    description="ページ上に多要素認証らしい記述がなかった。導入状況は画面からは判断できないため、質問票で確認する。",
                    remediation="管理者や重要機能のログインに多要素認証を導入する。導入済みなら本項目は質問票で実施済みと回答する。",
                    evidence={"url": url},
                )
            ]
        return []
