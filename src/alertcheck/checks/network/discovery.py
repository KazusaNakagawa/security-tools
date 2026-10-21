"""discovery: public hosts under the scope domains vs. the asset inventory (IPA P1-1).

Subdomain names come from certificate transparency (crt.sh). Only the
domain name is sent there; no request is made to the discovered hosts, and
names outside the scope or excluded are dropped before resolution.
"""

from __future__ import annotations

import asyncio
import csv
import io
from typing import ClassVar, Literal
from urllib.parse import quote, urlsplit

import httpx

from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

CRT_SH = "https://crt.sh/?q={query}&output=json"
_MAX_NAMES = 300
_HOST_COLUMNS = ("host", "hostname", "fqdn", "domain", "url")


def _hostname(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urlsplit(value).hostname or ""
    return value.lower().rstrip(".").split("/")[0]


def parse_inventory(text: str) -> set[str]:
    reader = csv.DictReader(io.StringIO(text))
    columns = [c for c in (reader.fieldnames or []) if c and c.strip().lower() in _HOST_COLUMNS]
    hosts = set()
    for row in reader:
        for column in columns:
            if row.get(column) and (host := _hostname(row[column])):
                hosts.add(host)
    return hosts


class DiscoveryCheck:
    id: ClassVar[str] = "discovery"
    group: ClassVar[Literal["network"]] = "network"
    ipa_items: ClassVar[list[str]] = ["P1-1"]
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    def _domains(self, ctx: Context) -> list[str]:
        return [d for d in ctx.scope.targets.domains if ctx.guard.check_host(d).allowed]

    def plan(self, ctx: Context) -> list[Coverage]:
        domains = self._domains(ctx)
        if not domains:
            return [
                Coverage(
                    check_id=self.id,
                    target="*",
                    status="skipped_no_input",
                    detail="no domain targets",
                )
            ]
        return [Coverage(check_id=self.id, target=d, status="executed") for d in domains]

    async def run(self, ctx: Context) -> CheckResult:
        domains = self._domains(ctx)
        result = CheckResult()
        inventory: set[str] | None = None
        if ctx.scope.asset_inventory:
            try:
                with ctx.infra.workspace.open_input(ctx.scope.asset_inventory) as f:
                    inventory = parse_inventory(f.read().decode("utf-8-sig"))
            except (OSError, PermissionError, UnicodeDecodeError, csv.Error) as e:
                detail = f"asset inventory unreadable: {e}"
                result.coverage = [
                    Coverage(check_id=self.id, target=d, status="error", detail=detail)
                    for d in domains
                ]
                return result

        discovered: set[str] = set()
        async with httpx.AsyncClient(
            timeout=30, trust_env=False, transport=self._transport
        ) as client:
            for domain in domains:
                names, note = await self._ct_names(ctx, client, domain)
                names.add(domain)
                in_scope = sorted(n for n in names if ctx.guard.check_host(n).allowed)[:_MAX_NAMES]
                resolved = await asyncio.gather(*(ctx.guard.resolve(n) for n in in_scope))
                live = {n for n, addrs in zip(in_scope, resolved, strict=True) if addrs}
                discovered |= live
                detail = f"{len(live)} resolvable host(s)" + (f"; {note}" if note else "")
                result.coverage.append(
                    Coverage(check_id=self.id, target=domain, status="executed", detail=detail)
                )
                if inventory is None and live:
                    result.findings.append(self._no_inventory(domain, sorted(live)))

        if inventory is not None:
            for host in sorted(discovered - inventory):
                result.findings.append(self._unlisted(host))
            scoped_inventory = sorted(h for h in inventory if ctx.guard.check_host(h).allowed)
            resolved = await asyncio.gather(*(ctx.guard.resolve(h) for h in scoped_inventory))
            for host, addrs in zip(scoped_inventory, resolved, strict=True):
                if not addrs:
                    result.findings.append(self._unresolved(host))
        result.artifacts["hosts"] = sorted(discovered)
        return result

    async def _ct_names(
        self, ctx: Context, client: httpx.AsyncClient, domain: str
    ) -> tuple[set[str], str]:
        ctx.audit({"event": "crtsh", "domain": domain})
        try:
            response = await client.get(CRT_SH.format(query=quote(f"%.{domain}")))
            response.raise_for_status()
            rows = response.json()
        except (httpx.HTTPError, ValueError) as e:
            return set(), f"crt.sh unavailable ({type(e).__name__})"
        names = set()
        for row in rows if isinstance(rows, list) else []:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().rstrip(".")
                if name and not name.startswith("*"):
                    names.add(name)
        return names, ""

    def _unlisted(self, host: str) -> Finding:
        return Finding.create(
            check_id=self.id,
            kind="unlisted_host",
            target=host,
            ipa_items=["P1-1"],
            severity=Severity.medium,
            title=f"資産台帳にない公開ホストを検出（{host}）",
            description="証明書の発行記録から見つかり、現在も名前解決できるが、資産台帳に載っていない。管理されていない公開サービスの可能性がある。",
            remediation="用途と管理者を確認して台帳に登録する。不要なら公開を停止し、DNS レコードを削除する。",
            evidence={"kind": "unlisted_host", "host": host, "source": "crt.sh"},
        )

    def _unresolved(self, host: str) -> Finding:
        return Finding.create(
            check_id=self.id,
            kind="unresolved_inventory_host",
            target=host,
            ipa_items=["P1-1"],
            severity=Severity.info,
            title=f"資産台帳のホストが名前解決できない（{host}）",
            description="台帳が実態と合っていない可能性がある。",
            remediation="廃止済みなら台帳から削除し、稼働中なら DNS 設定を確認する。",
            evidence={"kind": "unresolved_inventory_host", "host": host},
        )

    def _no_inventory(self, domain: str, hosts: list[str]) -> Finding:
        return Finding.create(
            check_id=self.id,
            kind="no_inventory",
            target=domain,
            ipa_items=["P1-1"],
            severity=Severity.info,
            title=f"{domain} 配下で公開ホストを {len(hosts)} 件検出（資産台帳なしのため未照合）",
            description="資産台帳（scope.yaml の asset_inventory）を指定すると、台帳にない公開ホストを検出できる。",
            remediation="外部公開アプリケーション・サービスの一覧を作成し、asset_inventory に指定する。",
            evidence={"kind": "no_inventory", "hosts": hosts[:100]},
        )
