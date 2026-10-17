"""vuln.templates: nuclei with the non-intrusive exposure/misconfig/tech templates.

Design §7.3. nuclei opens its own connections, so only hosts the Scope Guard
authorizes host-wide (domain / IP / CIDR targets) and whose DNS resolution
was validated are passed; redirects and out-of-band callbacks are disabled,
and the run is recorded in the audit log. nuclei resolves names itself, so
the address pinning that GuardedHttpClient applies is not available here.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import ClassVar, Literal
from urllib.parse import urlsplit

from alertcheck.adapters import nuclei
from alertcheck.adapters.process import Runner, ToolFailed, ToolNotFound, run_tool
from alertcheck.checks.network.base import http_targets
from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity
from alertcheck.core.scope_guard import redact_url
from alertcheck.vulndb import KevCatalog

_TIMEOUT = 1800
_SEVERITY = {
    "critical": Severity.high,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
}


class VulnTemplatesCheck:
    id: ClassVar[str] = "vuln.templates"
    group: ClassVar[Literal["network"]] = "network"
    ipa_items: ClassVar[list[str]] = ["A-1", "A-6", "P1-4"]
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(self, runner: Runner | None = None, cache: Path | None = None) -> None:
        self._runner = runner or run_tool
        self._cache = cache

    def _targets(self, ctx: Context) -> tuple[list[str], list[str]]:
        allowed, prefix_only = [], []
        for t in http_targets(ctx):
            host = urlsplit(t.url).hostname or ""
            (allowed if ctx.guard.check_host(host).allowed else prefix_only).append(t.url)
        return allowed, prefix_only

    def _prefix_skip(self, url: str) -> Coverage:
        return Coverage(
            check_id=self.id,
            target=url,
            status="skipped_by_option",
            detail="URL-prefix target only; add a domain/IP target to authorize template scanning",
        )

    def plan(self, ctx: Context) -> list[Coverage]:
        allowed, prefix_only = self._targets(ctx)
        coverage = [Coverage(check_id=self.id, target=u, status="executed") for u in allowed]
        coverage += [self._prefix_skip(u) for u in prefix_only]
        return coverage or [
            Coverage(
                check_id=self.id, target="*", status="skipped_no_input", detail="no HTTP targets"
            )
        ]

    async def run(self, ctx: Context) -> CheckResult:
        allowed, prefix_only = self._targets(ctx)
        result = CheckResult(coverage=[self._prefix_skip(u) for u in prefix_only])

        validated = []
        for url in allowed:
            decision = await ctx.guard.validate_resolution(urlsplit(url).hostname or "")
            if decision.allowed:
                validated.append(url)
            else:
                result.coverage.append(
                    Coverage(check_id=self.id, target=url, status="error", detail=decision.reason)
                )
        if not validated:
            return result

        limits = ctx.scope.limits
        with tempfile.TemporaryDirectory() as tmp:
            list_file = Path(tmp) / "targets.txt"
            list_file.write_text("\n".join(validated) + "\n", encoding="utf-8")
            ctx.audit({"event": "nuclei", "targets": [redact_url(u) for u in validated]})
            argv = nuclei.args(
                str(list_file),
                rps=limits.rps_per_host,
                concurrency=limits.concurrency,
                timeout=limits.timeout_sec,
            )
            try:
                output = await self._runner(argv, timeout=_TIMEOUT)
            except (ToolNotFound, ToolFailed) as e:
                detail = str(e)[:300]
                result.coverage += [
                    Coverage(check_id=self.id, target=u, status="error", detail=detail)
                    for u in validated
                ]
                return result

        kev = KevCatalog.load(self._cache)
        technologies: dict[str, list[str]] = {}
        for hit in nuclei.parse(output):
            if "tech" in hit.tags:
                if hit.matcher:
                    technologies.setdefault(hit.host, []).append(hit.matcher)
                continue
            if hit.severity not in _SEVERITY:
                continue  # info-level hits overlap the dedicated http.* checks
            result.findings.append(self._finding(hit, kev))
        if technologies:
            result.artifacts["technologies"] = technologies
        result.coverage += [
            Coverage(check_id=self.id, target=u, status="executed") for u in validated
        ]
        return result

    def _finding(self, hit: nuclei.NucleiHit, kev: KevCatalog) -> Finding:
        in_kev = any(kev.contains(c) for c in hit.cves)
        severity = _SEVERITY[hit.severity]
        if in_kev or (hit.severity == "critical" and "exposure" in hit.tags):
            severity = Severity.critical
        if hit.cves:
            ipa = ["P1-4"]
        elif "exposure" in hit.tags:
            ipa = ["A-1"]
        else:
            ipa = ["A-6"]
        target = redact_url(hit.matched_at) if "://" in hit.matched_at else hit.matched_at
        return Finding.create(
            check_id=self.id,
            kind=f"nuclei:{hit.template_id}",
            target=target,
            ipa_items=ipa,
            severity=severity,
            title=hit.name or hit.template_id,
            description=f"nuclei テンプレート {hit.template_id} に一致した。"
            + ("（CISA KEV 掲載: 実際の悪用が確認されている）" if in_kev else ""),
            remediation="該当箇所を確認し、更新・設定変更・公開範囲の制限で対処する。",
            evidence={
                "kind": "nuclei",
                "template": hit.template_id,
                "tags": list(hit.tags),
                "cves": list(hit.cves),
                "kev": in_kev,
                "matched_at": target,
            },
            references=[f"https://cloud.projectdiscovery.io/public/{hit.template_id}"],
        )
