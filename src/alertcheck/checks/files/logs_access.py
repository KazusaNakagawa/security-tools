"""logs.access: review access logs for anomalies and coverage (design §7.4).

IPA P1-2 / P1-3 (log review, coverage), A-5 (log fields). Logs are streamed
record by record; only per-day counters and small top-N structures are kept,
and distinct-key structures are capped, so a multi-GB log is processed in bounded memory.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import ClassVar, Literal

from alertcheck.checks.files.log_analysis import LogStats, coverage_days, zscore_anomalies
from alertcheck.checks.files.log_parser import parse_stream
from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

_ZSCORE = 3.0
_5XX_RATIO = 0.05
_IP_SHARE = 0.20
_SIG_REF = "https://www.ipa.go.jp/security/vuln/websecurity.html"


class LogsAccessCheck:
    id: ClassVar[str] = "logs.access"
    group: ClassVar[Literal["files"]] = "files"
    ipa_items: ClassVar[list[str]] = ["P1-2", "P1-3", "A-5"]
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(self, today: dt.date | None = None) -> None:
        self._today = today or dt.date.today()

    def plan(self, ctx: Context) -> list[Coverage]:
        if not ctx.scope.inputs.access_logs:
            return [
                Coverage(
                    check_id=self.id, target="*", status="skipped_no_input", detail="no access logs"
                )
            ]
        return [
            Coverage(check_id=self.id, target=e.path, status="executed")
            for e in ctx.scope.inputs.access_logs
        ]

    async def run(self, ctx: Context) -> CheckResult:
        allowlist = self._load_allowlist(ctx)
        stats = LogStats(allowlist=allowlist)
        errors = []
        parsed = 0
        for entry in ctx.scope.inputs.access_logs:
            for path in self._expand(ctx, entry.path):
                try:
                    with ctx.infra.workspace.open_input(path) as f:
                        for record in parse_stream(f, fmt=entry.format):
                            stats.add(record)
                            parsed += 1
                except (OSError, PermissionError, ValueError) as e:
                    errors.append(f"{path}: {e}")

        result = CheckResult()
        if errors and parsed == 0:
            result.coverage.append(
                Coverage(
                    check_id=self.id, target="logs", status="error", detail="; ".join(errors)[:300]
                )
            )
            return result

        cov = coverage_days(stats.timestamps, today=self._today)
        result.findings += self._anomaly_findings(stats)
        result.findings += self._coverage_findings(cov)
        result.findings += self._field_findings(stats)
        detail = self._coverage_detail(cov, parsed)
        if errors:
            detail += f"; 一部読み込み失敗: {'; '.join(errors)[:150]}"
        result.coverage.append(
            Coverage(check_id=self.id, target="logs", status="executed", detail=detail)
        )
        return result

    def _expand(self, ctx: Context, pattern: str) -> list[str]:
        if any(ch in pattern for ch in "*?["):
            return ctx.infra.workspace.glob_inputs(pattern)
        return [pattern]

    def _load_allowlist(self, ctx: Context) -> list[re.Pattern[str]] | None:
        if not ctx.scope.url_allowlist:
            return None
        try:
            with ctx.infra.workspace.open_input(ctx.scope.url_allowlist) as f:
                lines = f.read().decode("utf-8-sig").splitlines()
        except (OSError, PermissionError, UnicodeDecodeError):
            return None
        patterns = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    patterns.append(re.compile(line))
                except re.error:
                    continue
        return patterns

    def _coverage_detail(self, cov, parsed: int) -> str:
        if cov.oldest is None:
            return f"{parsed} 行、日時を持つレコードなし"
        window = (
            "直近90日を満たす"
            if cov.covers_90
            else (
                "直近30日を満たす（P1-3は90日分が必要）" if cov.covers_30 else "直近30日に満たない"
            )
        )
        return f"{parsed} 行、{cov.oldest}〜{cov.newest}、{window}"

    def _anomaly_findings(self, stats: LogStats) -> list[Finding]:
        out: list[Finding] = []
        for sig_id, info in stats.signature_hits.items():
            has_200 = info["hits_200"] > 0
            out.append(
                self._finding(
                    "attack_signature",
                    f"sig:{sig_id}",
                    Severity.high if has_200 else Severity.medium,
                    ["P1-2"],
                    f"ログに攻撃の痕跡（{info['label']}）",
                    f"{info['label']} に一致するリクエストが {info['count']} 件あった。"
                    + (
                        "うち 200 応答があり、成功した可能性がある。"
                        if has_200
                        else "いずれも成功応答ではないが、攻撃の試行を示す。"
                    ),
                    "該当リクエストと応答内容を精査し、成功していれば影響範囲を調査する。入力値の検証とパッチ適用を確認する。",
                    {
                        "signatures": [sig_id],
                        "count": info["count"],
                        "hits_200": info["hits_200"],
                        "example": info["example"],
                    },
                    refs=[_SIG_REF],
                )
            )

        for metric, counter, label in [
            ("total", stats.daily_total, "総リクエスト数"),
            ("4xx", stats.daily_4xx, "4xx 応答数"),
            ("5xx", stats.daily_5xx, "5xx 応答数"),
        ]:
            for anomaly in zscore_anomalies(dict(counter), threshold=_ZSCORE):
                out.append(
                    self._finding(
                        "traffic_anomaly",
                        f"{metric}:{anomaly.day}",
                        Severity.medium,
                        ["P1-2"],
                        f"{anomaly.day} の{label}が平時と大きく異なる",
                        f"{anomaly.day} の{label}は {anomaly.value}（平均 {anomaly.mean:.0f}、z={anomaly.z:.1f}）。侵害や障害の兆候がないか確認する。",
                        "該当日のログを詳しく調べ、原因を特定する。",
                        {
                            "metric": metric,
                            "day": anomaly.day.isoformat(),
                            "value": anomaly.value,
                            "z": round(anomaly.z, 1),
                        },
                    )
                )

        for day, total in stats.daily_total.items():
            fivexx = stats.daily_5xx.get(day, 0)
            if total >= 20 and fivexx / total > _5XX_RATIO:
                out.append(
                    self._finding(
                        "error_spike",
                        f"5xx:{day}",
                        Severity.medium,
                        ["P1-2"],
                        f"{day} の 5xx 応答比率が高い",
                        f"{day} は {total} 件中 {fivexx} 件（{fivexx / total:.0%}）が 5xx 応答だった。",
                        "サーバ側のエラー原因を調査する。攻撃による異常でないかも確認する。",
                        {"day": day.isoformat(), "total": total, "fivexx": fivexx},
                    )
                )

        if stats.allowlist is not None:
            for url, count in stats.unexpected_200.most_common(50):
                out.append(self._unexpected(url, count))
        else:
            for url in stats.webshell_candidates()[:50]:
                out.append(
                    self._unexpected(url, stats.webshell_suspect[url].__len__(), webshell=True)
                )

        if stats.total:
            ip, count = stats.top_ip()[0] if stats.top_ip() else ("", 0)
            if count / stats.total >= _IP_SHARE and count >= 50:
                out.append(
                    self._finding(
                        "ip_concentration",
                        f"ip:{ip}",
                        Severity.medium,
                        ["P1-2"],
                        f"単一の送信元 IP からのアクセスが集中している（{ip}）",
                        f"{ip} からのリクエストが全体の {count / stats.total:.0%}（{count} 件）を占める。",
                        "正当な利用か確認する。攻撃やスクレイピングなら送信元を遮断し、レート制限を検討する。",
                        {"ip": ip, "count": count, "share": round(count / stats.total, 3)},
                    )
                )
        return out

    def _unexpected(self, url: str, count: int, *, webshell: bool = False) -> Finding:
        title = (
            "Web シェルの疑いがある URL への 200 応答"
            if webshell
            else "許可リストにない URL への 200 応答"
        )
        return self._finding(
            "unexpected_200",
            f"url:{url}",
            Severity.medium if webshell else Severity.low,
            ["P1-2"],
            f"{title}（{url[:80]}）",
            f"{url[:200]} への 200 応答が {count} 件あった。想定しない公開や、設置された不正ファイルの可能性がある。",
            "URL の内容を確認する。設置した覚えのないファイルなら削除し、設置経路を調査する。",
            {"url": url[:200], "count": count, "webshell_suspect": webshell},
        )

    def _coverage_findings(self, cov) -> list[Finding]:
        if cov.oldest is None:
            return [
                self._finding(
                    "coverage_gap",
                    "no_dates",
                    Severity.low,
                    ["P1-2", "P1-3"],
                    "アクセスログに日時を持つレコードがない",
                    "ログ形式が合っていないか、日時が記録されていない。期間の確認ができない。",
                    "ログ形式の指定を確認し、日時を含む形式で保存する。",
                    {"covers_30": False, "covers_90": False},
                )
            ]
        if not cov.covers_90:
            target = "直近30日分" if not cov.covers_30 else "直近90日分"
            return [
                self._finding(
                    "coverage_gap",
                    "window",
                    Severity.low,
                    ["P1-3"] if cov.covers_30 else ["P1-2", "P1-3"],
                    f"確認できるログ期間が不足している（{target}に満たない）",
                    f"ログは {cov.oldest} からで、P1-3 が求める直近90日分に満たない。P1-2 は直近30日、P1-3 は直近90日分のログが必要。",
                    "直近90日分のアクセスログを揃えて再診断する。ログの保持期間を見直す。",
                    {
                        "oldest": cov.oldest.isoformat(),
                        "covers_30": cov.covers_30,
                        "covers_90": cov.covers_90,
                    },
                )
            ]
        return []

    def _field_findings(self, stats: LogStats) -> list[Finding]:
        missing = []
        if stats.missing_ip > 0:
            missing.append("送信元 IP")
        if stats.total and stats.missing_user == stats.total:
            missing.append("ユーザー識別子")
        if not missing:
            return []
        return [
            self._finding(
                "missing_log_fields",
                "fields",
                Severity.low,
                ["A-5"],
                "調査に必要なログ項目が不足している",
                f"ログに {', '.join(missing)} が含まれていない。インシデント調査に支障が出る。",
                "日時・送信元 IP・操作者・操作内容を含むログ形式に見直す。",
                {"missing": missing},
            )
        ]

    def _finding(
        self, kind, variant, severity, ipa, title, description, remediation, evidence, refs=None
    ):
        return Finding.create(
            check_id=self.id,
            kind=f"{kind}:{variant}",
            target=f"logs/{variant}",
            ipa_items=ipa,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence={"kind": kind, **evidence},
            references=refs or [],
        )
