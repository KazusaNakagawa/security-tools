"""http.errors: stack traces and SQL error messages in error responses.

Design §7.3, IPA A-6. Only malformed-but-harmless inputs are sent (a missing
path, an array where a scalar is expected, a lone quote, an invalid byte);
no injection payloads.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from urllib.parse import urljoin

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget, fetch
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation

_IPA = ["A-6"]
PROBES = ["{token}", "{token}.php", "{token}.aspx", "?id[]=1", "?id=%27", "?page=%ff"]

STACK_TRACES: list[tuple[str, re.Pattern[str]]] = [
    ("python", re.compile(r"Traceback \(most recent call last\)")),
    ("django", re.compile(r"you have <code>DEBUG = True</code>", re.IGNORECASE)),
    ("java", re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)|Exception in thread \"")),
    (
        "php",
        re.compile(r"(Fatal error|Parse error|Warning)</b>:|\bStack trace:\s*\n?#0|on line <b>\d+"),
    ),
    ("node", re.compile(r"\n\s+at .+\(?/[^\s]+\.(?:js|ts|mjs):\d+:\d+\)?")),
    ("dotnet", re.compile(r"Server Error in '/' Application|System\.\w+Exception")),
    ("laravel", re.compile(r"Whoops! There was an error|Illuminate\\\\")),
    ("rails", re.compile(r"ActionController::\w+Error|ActiveRecord::\w+")),
    ("ruby", re.compile(r"\.rb:\d+:in `")),
]
SQL_ERRORS = re.compile(
    "|".join(
        [
            r"You have an error in your SQL syntax",
            r"SQLSTATE\[\w+\]",
            r"\bORA-\d{5}\b",
            r"PG::\w+Error",
            r"pg_query\(\)",
            r"unterminated quoted string",
            r"Unclosed quotation mark after the character string",
            r"SQLite3?::\w*Exception",
            r"Microsoft OLE DB Provider for SQL Server",
            r"mysqli?_\w+\(\)",
        ]
    ),
    re.IGNORECASE,
)
_EXCERPT = 120


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - _EXCERPT)
    return text[start : match.end() + _EXCERPT][: 2 * _EXCERPT + 60]


class HttpErrorsCheck(HttpCheck):
    id = "http.errors"
    ipa_items = _IPA

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> list[Finding]:
        base = target.url if target.url.endswith("/") else target.url + "/"
        token = secrets.token_hex(8)
        urls = [urljoin(base, p.format(token=token)) for p in PROBES]
        responses = await asyncio.gather(*(self._get(ctx, u) for u in urls))

        found: dict[str, Finding] = {}
        for url, resp in zip(urls, responses, strict=True):
            if resp is None:
                continue
            text = resp.text
            if "stack_trace" not in found:
                for framework, pattern in STACK_TRACES:
                    if m := pattern.search(text):
                        found["stack_trace"] = self.finding(
                            kind="stack_trace",
                            target=target.url,
                            severity=Severity.medium,
                            ipa_items=_IPA,
                            title="エラー応答にスタックトレースが表示される",
                            description="内部のファイルパス、フレームワーク、処理の流れが外部に見え、攻撃の手掛かりになる。",
                            remediation="本番環境ではデバッグ表示を無効化し、利用者には汎用のエラーページを返す。",
                            evidence={
                                "framework": framework,
                                "url": url,
                                "status": resp.status_code,
                                "excerpt": _excerpt(text, m),
                            },
                        )
                        break
            if "sql_error" not in found and (m := SQL_ERRORS.search(text)):
                found["sql_error"] = self.finding(
                    kind="sql_error",
                    target=target.url,
                    severity=Severity.high,
                    ipa_items=_IPA,
                    title="エラー応答にデータベースのエラー文が表示される",
                    description="入力値がそのまま SQL に渡っている可能性があり、SQL インジェクションの兆候である。手動での確認を推奨する。",
                    remediation="プレースホルダ（パラメータ化クエリ）を使い、DB のエラーを利用者に返さない。",
                    evidence={"url": url, "status": resp.status_code, "excerpt": _excerpt(text, m)},
                )
        return list(found.values())

    async def _get(self, ctx: Context, url: str) -> httpx.Response | None:
        try:
            return await fetch(ctx, url, max_body=128 * 1024)
        except (httpx.HTTPError, ScopeViolation):
            return None
