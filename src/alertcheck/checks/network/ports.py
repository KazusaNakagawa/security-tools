"""ports: internet-exposed remote admin, database and container ports (design §7.3).

IPA A-1 (exposure), P1-1 / P2-1 (inventory). nmap runs a TCP connect scan
against addresses the Scope Guard validated: domains are passed as their
pinned IP (nmap is told not to resolve names), only targets authorized
host-wide are included, and excluded networks are passed as --exclude.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import ClassVar, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field

from alertcheck.adapters import nmap
from alertcheck.adapters.process import Runner, ToolFailed, ToolNotFound, run_tool
from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

_TIMEOUT = 3600
_WEB_PORTS = (80, 443)


@dataclass(frozen=True)
class Category:
    severity: Severity
    ipa_items: list[str]
    title: str
    description: str
    remediation: str


CATEGORIES = {
    "legacy_cleartext": Category(
        Severity.high,
        ["A-1"],
        "平文の管理プロトコルが公開されている",
        "通信が暗号化されず、認証情報を盗聴されうる。",
        "サービスを停止するか、SSH / SFTP など暗号化された手段に置き換え、外部からのアクセスを遮断する。",
    ),
    "remote_admin": Category(
        Severity.high,
        ["A-1"],
        "リモート管理用のポートがインターネットに公開されている",
        "パスワード推測や既知の脆弱性による侵入の入口になる。",
        "VPN や踏み台経由に限定し、送信元 IP を制限する。多要素認証を有効にする。",
    ),
    "database": Category(
        Severity.high,
        ["A-1", "D-2"],
        "データベースがインターネットに公開されている",
        "認証の不備や脆弱性があれば、保有データを直接取得されうる。",
        "データベースは内部ネットワークからのみ接続できるようにし、外部公開を停止する。",
    ),
    "container": Category(
        Severity.high,
        ["A-1"],
        "コンテナ基盤の管理 API がインターネットに公開されている",
        "管理 API を悪用されるとホスト全体を乗っ取られうる。",
        "管理 API を内部ネットワークに限定し、認証と TLS を必須にする。",
    ),
    "admin_web": Category(
        Severity.low,
        ["A-1"],
        "管理用途の可能性があるポートが公開されている",
        "管理画面や開発用サーバが公開されている可能性がある。",
        "提供内容を確認し、不要なら外部公開を停止する。",
    ),
    "vpn": Category(
        Severity.info,
        ["P2-1"],
        "VPN 機器が使うポートが公開されている",
        "VPN 機器は不正アクセスの侵入口として悪用が相次いでいる。外部サービス台帳への登録と更新状況を確認する。",
        "ファームウェアを最新にし、多要素認証を有効にし、ログイン履歴を確認する。",
    ),
}


class PortRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = Field(ge=1, le=65535)
    category: str
    label: str
    severity: Severity | None = None
    services: list[str] = Field(default_factory=list)


@cache
def load_ports() -> list[PortRule]:
    raw = files("alertcheck.data").joinpath("admin_ports.yaml").read_text(encoding="utf-8")
    rules = [PortRule.model_validate(r) for r in yaml.safe_load(raw)]
    for r in rules:
        if r.category not in CATEGORIES:
            raise ValueError(f"unknown port category {r.category!r}")
    return rules


class PortsCheck:
    id: ClassVar[str] = "ports"
    group: ClassVar[Literal["network"]] = "network"
    ipa_items: ClassVar[list[str]] = ["A-1", "P1-1", "P2-1"]
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or run_tool

    def _labels(self, ctx: Context) -> tuple[list[str], list[str]]:
        """(host-wide authorized targets, URL-prefix-only hosts)."""
        targets = ctx.scope.targets
        allowed = [d for d in targets.domains if ctx.guard.check_host(d).allowed]
        allowed += [h for h in targets.hosts if ctx.guard.check_host(h).allowed]
        allowed += list(targets.cidrs) if ctx.guard.authorized else []
        prefix_only = []
        for url in targets.urls:
            host = urlsplit(url).hostname or ""
            if host and not ctx.guard.check_host(host).allowed and host not in prefix_only:
                prefix_only.append(host)
        return allowed, prefix_only

    def _skip(self, host: str) -> Coverage:
        return Coverage(
            check_id=self.id,
            target=host,
            status="skipped_by_option",
            detail="URL-prefix target only; add a domain/IP target to authorize a port scan",
        )

    def plan(self, ctx: Context) -> list[Coverage]:
        allowed, prefix_only = self._labels(ctx)
        coverage = [Coverage(check_id=self.id, target=t, status="executed") for t in allowed]
        coverage += [self._skip(h) for h in prefix_only]
        return coverage or [
            Coverage(
                check_id=self.id, target="*", status="skipped_no_input", detail="no host targets"
            )
        ]

    async def run(self, ctx: Context) -> CheckResult:
        allowed, prefix_only = self._labels(ctx)
        result = CheckResult(coverage=[self._skip(h) for h in prefix_only])

        # address handed to nmap -> label used in findings
        addresses: dict[str, str] = {}
        for label in allowed:
            if "/" in label:  # CIDR: nmap expands it; excludes are passed separately
                addresses[label] = label
                continue
            decision = await ctx.guard.check_resolved(label)
            address = ctx.guard.pinned_address(label) if decision.allowed else None
            if address is None:
                reason = decision.reason or "no validated address"
                result.coverage.append(
                    Coverage(check_id=self.id, target=label, status="error", detail=reason)
                )
                continue
            addresses.setdefault(address, label)
        if not addresses:
            return result

        rules = load_ports()
        ports = sorted({r.port for r in rules} | set(_WEB_PORTS))
        with tempfile.TemporaryDirectory() as tmp:
            target_file = Path(tmp) / "targets.txt"
            target_file.write_text("\n".join(addresses) + "\n", encoding="utf-8")
            ctx.audit({"event": "nmap", "targets": list(addresses)})
            argv = nmap.args(
                str(target_file),
                ports=ports,
                rate=ctx.scope.limits.rps_per_host * 10,
                excludes=ctx.guard.tool_excludes(),
            )
            try:
                hosts = nmap.parse(await self._runner(argv, timeout=_TIMEOUT))
            except (ToolNotFound, ToolFailed, ValueError) as e:
                detail = str(e)[:300]
                result.coverage += [
                    Coverage(check_id=self.id, target=label, status="error", detail=detail)
                    for label in dict.fromkeys(addresses.values())
                ]
                return result

        open_ports: dict[str, list[int]] = {}
        for host in hosts:
            # addresses from a CIDR target are reported as themselves
            label = addresses.get(host.address, host.address)
            open_ports.setdefault(label, []).extend(p.port for p in host.ports)
            result.findings += [f for p in host.ports if (f := self._finding(label, p, rules))]
        result.artifacts["open_ports"] = {k: sorted(set(v)) for k, v in open_ports.items()}
        result.coverage += [
            Coverage(check_id=self.id, target=label, status="executed")
            for label in dict.fromkeys(addresses.values())
        ]
        return result

    def _finding(self, label: str, port: nmap.OpenPort, rules: list[PortRule]) -> Finding | None:
        rule = next((r for r in rules if r.port == port.port), None) or next(
            (r for r in rules if port.service and port.service in r.services), None
        )
        if rule is None:
            return None
        category = CATEGORIES[rule.category]
        return Finding.create(
            check_id=self.id,
            kind=f"exposed_port:{port.port}",
            target=f"{label}:{port.port}",
            ipa_items=category.ipa_items,
            severity=rule.severity or category.severity,
            title=f"{category.title}（{rule.label} / {port.port}）",
            description=category.description,
            remediation=category.remediation,
            evidence={
                "kind": "exposed_port",
                "port": port.port,
                "label": rule.label,
                "category": rule.category,
                "service": port.service,
                "product": port.product,
                "version": port.version,
            },
        )
