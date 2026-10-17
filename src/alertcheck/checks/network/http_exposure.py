"""http.exposure: publicly reachable secrets, dumps, backups and admin panels.

Design §7.3, IPA A-1 / D-2. Every hit must pass two filters before it is
reported: it must differ from the site's "not found" behaviour (soft-404
detection) and its content must match the rule for that path. Bodies are
read only partially and never copied into evidence, except variable names of
dotenv files.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import re
import secrets
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from alertcheck.checks.network.base import HttpCheck, HttpTarget, InspectResult, fetch, probe_base
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation

PROBE_MAX_BODY = 64 * 1024
_FAILED = object()  # sentinel: the probe request itself failed
_SIMILARITY = 0.9
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=")
_PASSWORD_INPUT = re.compile(r"type\s*=\s*[\"']?password", re.IGNORECASE)
_LISTING = re.compile(
    r"(<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /|\[To Parent Directory\])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Category:
    severity: Severity
    ipa_items: list[str]
    html: Literal["forbidden", "allowed"]
    title: str
    description: str
    remediation: str


_DATA_IPA = ["A-1", "D-2"]
CATEGORIES: dict[str, Category] = {
    "vcs": Category(
        Severity.critical,
        _DATA_IPA,
        "forbidden",
        "バージョン管理のメタデータが公開されている",
        "ソースコード全体や過去の変更履歴（削除した認証情報を含む）を取得されうる。",
        "公開ディレクトリから .git 等を削除し、Web サーバでドットファイルへのアクセスを拒否する。",
    ),
    "secret_file": Category(
        Severity.critical,
        _DATA_IPA,
        "forbidden",
        "認証情報を含む設定ファイルが公開されている",
        "データベースや外部サービスの認証情報が漏えいし、直接侵入されうる。",
        "ファイルを公開領域から移動し、含まれる認証情報をすべて無効化・再発行する。",
    ),
    "db_dump": Category(
        Severity.critical,
        _DATA_IPA,
        "forbidden",
        "データベースのダンプが公開されている",
        "保有データ（個人情報を含みうる）をそのまま取得されうる。",
        "ファイルを直ちに削除し、アクセスログで取得の有無を確認する。漏えいが疑われる場合は報告手順に従う。",
    ),
    "backup_archive": Category(
        Severity.high,
        _DATA_IPA,
        "forbidden",
        "サイトのバックアップが公開されている",
        "ソースコードや設定ファイルをまとめて取得されうる。",
        "バックアップを公開領域の外に保管する。",
    ),
    "source_backup": Category(
        Severity.high,
        _DATA_IPA,
        "forbidden",
        "ソースコードのバックアップが公開されている",
        "実行されずにソースとして返るため、処理内容や認証情報を読まれうる。",
        "不要なバックアップ・エディタの一時ファイルを削除する。",
    ),
    "log_file": Category(
        Severity.high,
        _DATA_IPA,
        "forbidden",
        "ログファイルが公開されている",
        "利用者情報、内部パス、エラー内容などを取得されうる。",
        "ログを公開領域の外に出力し、公開済みのファイルを削除する。",
    ),
    "info_page": Category(
        Severity.medium,
        ["A-1"],
        "allowed",
        "診断・デバッグ用のページが公開されている",
        "サーバ構成、環境変数、内部情報を取得されうる。",
        "本番環境で無効化するか、管理者のみがアクセスできるよう制限する。",
    ),
    "admin_panel": Category(
        Severity.medium,
        ["A-1"],
        "allowed",
        "管理画面がインターネットから到達できる",
        "パスワード推測やリスト型攻撃の標的になる。",
        "IP 制限や VPN 経由に限定し、多要素認証を導入する。",
    ),
    "dir_listing": Category(
        Severity.medium,
        ["A-1"],
        "allowed",
        "ディレクトリリスティングが有効になっている",
        "公開を意図していないファイルの一覧を閲覧されうる。",
        "Web サーバのディレクトリ一覧表示を無効化する（Apache: Options -Indexes）。",
    ),
    "manifest": Category(
        Severity.low,
        ["A-1"],
        "forbidden",
        "依存関係の定義ファイルが公開されている",
        "利用ライブラリとバージョンが分かり、既知の脆弱性を狙われやすくなる。",
        "公開領域に置かない、または Web サーバでアクセスを拒否する。",
    ),
    "build_config": Category(
        Severity.medium,
        ["A-1"],
        "forbidden",
        "ビルド・デプロイ設定が公開されている",
        "内部構成や、記載されている場合は認証情報を取得されうる。",
        "公開領域に置かない、または Web サーバでアクセスを拒否する。",
    ),
}


class MatchRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    any: list[str] = []
    regex: str | None = None
    magic: list[str] = []
    env: bool = False
    json_keys: list[str] = []
    login_form: bool = False

    @field_validator("regex")
    @classmethod
    def _compiles(cls, value: str | None) -> str | None:
        if value is not None:
            re.compile(value)
        return value

    @field_validator("magic")
    @classmethod
    def _hex(cls, values: list[str]) -> list[str]:
        for v in values:
            bytes.fromhex(v)
        return values

    def has_rule(self) -> bool:
        return bool(
            self.any or self.regex or self.magic or self.env or self.json_keys or self.login_form
        )

    def matches(self, body: bytes, text: str) -> bool:
        checks = []
        if self.any:
            checks.append(any(n in text for n in self.any))
        if self.regex:
            checks.append(re.search(self.regex, text, re.IGNORECASE | re.MULTILINE) is not None)
        if self.magic:
            checks.append(any(body.startswith(bytes.fromhex(m)) for m in self.magic))
        if self.env:
            checks.append(bool(env_keys(text)))
        if self.json_keys:
            checks.append(_has_json_keys(text, self.json_keys))
        if self.login_form:
            checks.append(_PASSWORD_INPUT.search(text) is not None)
        return bool(checks) and all(checks)


class PathRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    category: str
    severity: Severity | None = None
    match: MatchRule

    @model_validator(mode="after")
    def _valid(self) -> PathRule:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category {self.category!r} for {self.path}")
        if self.path.startswith("/"):
            raise ValueError(f"path must be relative: {self.path}")
        if not self.match.has_rule():
            raise ValueError(f"no match rule for {self.path}")
        return self


@cache
def load_paths() -> list[PathRule]:
    raw = files("alertcheck.data").joinpath("sensitive_paths.yaml").read_text(encoding="utf-8")
    return [PathRule.model_validate(entry) for entry in yaml.safe_load(raw)]


def env_keys(text: str) -> list[str]:
    """Variable names if the text looks like a dotenv file, else []."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    keys = [m.group(1) for ln in lines if (m := _ENV_LINE.match(ln))]
    if not keys or len(keys) / len(lines) < 0.6:
        return []
    return keys


def _has_json_keys(text: str, keys: list[str]) -> bool:
    try:
        data = json.loads(text)
    except ValueError:
        return False
    return isinstance(data, dict) and any(k in data for k in keys)


def looks_like_html(text: str) -> bool:
    head = text[:1024].lstrip().lower()
    return head.startswith(("<!doctype html", "<html")) or "<html" in head or "<body" in head


# bounded comparison input: keeps SequenceMatcher's worst case small on huge or
# repetitive bodies
_COMPARE_CHARS = 4096


def _normalize(text: str, *tokens: str) -> str:
    text = text[: _COMPARE_CHARS * 2]
    for token in tokens:
        if token:
            text = text.replace(token, "")
    text = re.sub(r"\d+", "0", text)
    return re.sub(r"\s+", " ", text).strip()[:_COMPARE_CHARS]


@dataclass
class _Baseline:
    samples: list[tuple[int, str, str]]  # (status, normalized body, probe path)

    def has_status(self, status: int) -> bool:
        return any(s == status for s, _, _ in self.samples)

    def is_soft_404(self, response: httpx.Response, path: str) -> bool:
        body = _normalize(response.text, path)
        for status, sample, _ in self.samples:
            if status != response.status_code:
                continue
            matcher = difflib.SequenceMatcher(None, sample, body)
            if (
                matcher.real_quick_ratio() >= _SIMILARITY
                and matcher.quick_ratio() >= _SIMILARITY
                and matcher.ratio() >= _SIMILARITY
            ):
                return True
        return False


class HttpExposureCheck(HttpCheck):
    id = "http.exposure"
    ipa_items = ["A-1", "D-2"]

    def __init__(self, paths: list[PathRule] | None = None) -> None:
        self._paths = paths

    async def _baseline(self, ctx: Context, base: str) -> _Baseline:
        token = secrets.token_hex(8)
        samples = []
        for probe in (token, f"{token}.php", f"{token}/"):
            try:
                resp = await fetch(ctx, urljoin(base, probe), max_body=PROBE_MAX_BODY)
            except (httpx.HTTPError, ScopeViolation):
                continue
            samples.append((resp.status_code, _normalize(resp.text, probe, token), probe))
        return _Baseline(samples)

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> InspectResult:
        base = probe_base(target.url)
        findings: list[Finding] = []
        if _LISTING.search(response.text):
            findings.append(self._finding(base, "", CATEGORIES["dir_listing"], None, response, {}))

        baseline = await self._baseline(ctx, base)
        rules = self._paths if self._paths is not None else load_paths()
        results = await asyncio.gather(*(self._probe(ctx, base, rule, baseline) for rule in rules))
        findings += [f for f in results if isinstance(f, Finding)]
        failed = sum(1 for f in results if f is _FAILED)
        return InspectResult(findings=findings, probes=len(rules), failed=failed)

    async def _probe(
        self, ctx: Context, base: str, rule: PathRule, baseline: _Baseline
    ) -> Finding | object | None:
        url = urljoin(base, rule.path)
        try:
            resp = await fetch(ctx, url, max_body=PROBE_MAX_BODY)
        except ScopeViolation:
            return None  # excluded by scope: intentionally not probed
        except httpx.HTTPError:
            return _FAILED
        category = CATEGORIES[rule.category]

        challenge = resp.headers.get("www-authenticate", "")
        if resp.status_code == 401 and rule.match.login_form and challenge:
            if baseline.has_status(401):
                return None  # the whole site challenges; says nothing about this path
            scheme = challenge.split()[0].lower()
            return self._finding(url, rule.path, category, Severity.low, resp, {"auth": scheme})
        if resp.status_code != 200:
            return None
        if resp.history:
            # only an admin path may legitimately redirect, and only to its own site's login page
            same_origin = urlsplit(str(resp.url)).netloc == urlsplit(url).netloc
            if rule.category != "admin_panel" or not same_origin:
                return None
        if baseline.is_soft_404(resp, rule.path):
            return None
        text = resp.text
        if category.html == "forbidden" and looks_like_html(text):
            return None
        if not rule.match.matches(resp.content, text):
            return None
        extra: dict[str, Any] = {}
        if rule.match.env:
            extra["keys"] = env_keys(text)[:30]
        return self._finding(url, rule.path, category, rule.severity, resp, extra)

    def _finding(
        self,
        url: str,
        path: str,
        category: Category,
        severity: Severity | None,
        resp: httpx.Response,
        extra: dict[str, Any],
    ) -> Finding:
        kind = next(k for k, v in CATEGORIES.items() if v is category)
        return self.finding(
            kind=kind,
            variant=path,
            target=url,
            severity=severity or category.severity,
            ipa_items=category.ipa_items,
            title=f"{category.title}: /{path}" if path else category.title,
            description=category.description,
            remediation=category.remediation,
            evidence={
                "path": path,
                "url": url,
                "status": resp.status_code,
                "content_type": resp.headers.get("content-type"),
                "truncated": bool(resp.extensions.get("alertcheck_truncated")),
                **extra,
            },
        )
