"""deps: known vulnerabilities and end-of-life runtimes in dependencies (design §7.4, IPA P1-4)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any, ClassVar, Literal

from alertcheck.adapters import osv, trivy
from alertcheck.adapters.process import Runner, ToolFailed, ToolNotFound, run_tool
from alertcheck.adapters.vulns import VulnRecord, merge_records, severity_from_cvss
from alertcheck.checks.files.runtimes import Runtime, detect_runtimes
from alertcheck.config.scope import DepInput
from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity
from alertcheck.vulndb import EolCatalog, EolStatus, KevCatalog

_IPA = ["P1-4"]
_TOOL_TIMEOUT = 900
_OS_PRODUCTS = {"alpine": "alpine-linux"}
_EOL_REF = "https://endoflife.date/"
_KEV_REF = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def _label(entry: DepInput) -> str:
    return entry.path if entry.path else f"image:{entry.image}"


def vuln_severity(record: VulnRecord, kev: bool) -> Severity:
    """Spec §5.1: critical is reserved for actively exploited (KEV) vulnerabilities."""
    if kev:
        return Severity.critical
    base = record.severity if record.severity != "unknown" else severity_from_cvss(record.cvss)
    mapped = {
        "critical": Severity.high,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
    }.get(base, Severity.low)
    if not record.fixed:
        # nothing to upgrade to yet: a reason to look at mitigations, not a missed patch
        return Severity.medium if mapped.rank >= Severity.medium.rank else Severity.low
    return mapped


class DepsCheck:
    id: ClassVar[str] = "deps"
    group: ClassVar[Literal["files"]] = "files"
    ipa_items: ClassVar[list[str]] = _IPA
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(
        self, runner: Runner | None = None, cache: Path | None = None, today: dt.date | None = None
    ) -> None:
        self._runner = runner or run_tool
        self._cache = cache
        self._today = today

    def plan(self, ctx: Context) -> list[Coverage]:
        entries = ctx.scope.inputs.deps
        if not entries:
            return [
                Coverage(
                    check_id=self.id, target="*", status="skipped_no_input", detail="no deps inputs"
                )
            ]
        return [Coverage(check_id=self.id, target=_label(e), status="executed") for e in entries]

    async def run(self, ctx: Context) -> CheckResult:
        kev = KevCatalog.load(self._cache)
        eol = EolCatalog.load(self._cache)
        result = CheckResult()
        for entry in ctx.scope.inputs.deps:  # one at a time: scanners are CPU and I/O heavy
            findings, coverage = await self._entry(ctx, entry, kev, eol)
            result.findings += findings
            result.coverage.append(coverage)
        return result

    async def _tool(
        self, argv: list[str], parse: Any, notes: list[str], ok_codes: tuple[int, ...] = (0,)
    ) -> Any:
        try:
            output = await self._runner(argv, timeout=_TOOL_TIMEOUT, ok_codes=ok_codes)
            return parse(output)
        except ToolNotFound:
            notes.append(f"{argv[0]} not installed")
        except (ToolFailed, ValueError) as e:
            notes.append(str(e)[:300])
        return None

    async def _entry(
        self, ctx: Context, entry: DepInput, kev: KevCatalog, eol: EolCatalog
    ) -> tuple[list[Finding], Coverage]:
        label = _label(entry)
        offline = ctx.options.offline
        notes: list[str] = []
        records: list[VulnRecord] = []
        runtimes: list[Runtime] = []
        os_info: tuple[str, str, bool] | None = None
        scanners_ran = 0

        if entry.path:
            try:
                local = ctx.infra.workspace.local_path(entry.path)
            except PermissionError as e:
                return [], Coverage(check_id=self.id, target=label, status="error", detail=str(e))
            if not local.exists():
                detail = f"path not found: {entry.path}"
                return [], Coverage(check_id=self.id, target=label, status="error", detail=detail)
            report = await self._tool(
                trivy.fs_args(str(local), offline=offline), trivy.parse, notes
            )
            if report is not None:
                scanners_ran += 1
                records += report.vulns
            osv_records = await self._tool(
                osv.args(str(local), offline=offline),
                lambda out: osv.parse(out, root=str(local)),
                notes,
                osv.OK_EXIT_CODES,
            )
            if osv_records is not None:
                scanners_ran += 1
                records += osv_records
            runtimes = detect_runtimes(local)
        else:
            assert entry.image is not None
            report = await self._tool(
                trivy.image_args(entry.image, offline=offline), trivy.parse, notes
            )
            if report is not None:
                scanners_ran += 1
                records += report.vulns
                os_info = report.os

        if not kev.available:
            notes.append("KEV data not available; run 'alertcheck db update'")

        findings = [self._vuln_finding(label, r, kev) for r in merge_records(records)]
        findings += [f for rt in runtimes if (f := self._runtime_finding(label, rt, eol))]
        if os_info and (f := self._os_finding(label, os_info, eol)):
            findings.append(f)

        if scanners_ran == 0:
            notes.insert(0, "no vulnerability scanner ran")
            return findings, Coverage(
                check_id=self.id, target=label, status="error", detail="; ".join(notes)
            )
        return findings, Coverage(
            check_id=self.id, target=label, status="executed", detail="; ".join(notes)
        )

    def _vuln_finding(self, label: str, r: VulnRecord, kev: KevCatalog) -> Finding:
        in_kev = any(kev.contains(c) for c in r.cves)
        kind = "unpatched" if r.fixed else "no_fix"
        if r.fixed:
            remediation = f"{r.package} を {r.fixed} 以上に更新する。"
        else:
            remediation = (
                "修正版が提供されていないため、影響する機能の利用有無を確認し、"
                "代替策（機能の無効化、入力の制限、WAF による緩和、別ライブラリへの置き換え）を検討する。"
            )
        description = r.title or f"{r.package} {r.installed} に既知の脆弱性がある。"
        if in_kev:
            description += "（CISA KEV 掲載: 実際の悪用が確認されている）"
        target = f"{label}/{r.target}" if r.target and not label.startswith("image:") else label
        return Finding.create(
            check_id=self.id,
            kind=f"{kind}:{r.key}|{r.package}|{r.installed}",
            target=target,
            ipa_items=_IPA,
            severity=vuln_severity(r, in_kev),
            title=f"{r.package} {r.installed} に既知の脆弱性（{r.key}）",
            description=description,
            remediation=remediation,
            evidence={
                "kind": kind,
                "vuln": r.key,
                "package": r.package,
                "ecosystem": r.ecosystem,
                "installed": r.installed,
                "fixed": r.fixed,
                "cves": r.cves,
                "cvss": r.cvss,
                "kev": in_kev,
                "sources": sorted(r.sources),
            },
            references=[u for u in (r.url, _KEV_REF if in_kev else None) if u],
        )

    def _eol(self, eol: EolCatalog, product: str, version: str) -> EolStatus | None:
        status = eol.status(product, version, today=self._today)
        return status if status and status.is_eol else None

    def _runtime_finding(self, label: str, rt: Runtime, eol: EolCatalog) -> Finding | None:
        status = self._eol(eol, rt.product, rt.version)
        if status is None:
            return None
        since = f"（{status.eol.isoformat()} に終了）" if status.eol else ""
        return Finding.create(
            check_id=self.id,
            kind=f"eol_runtime:{rt.product}|{rt.source}|{rt.version}",
            target=f"{label}/{rt.source}",
            ipa_items=_IPA,
            severity=Severity.high,
            title=f"サポートが終了した {rt.product} {status.cycle} を使用している{since}",
            description="セキュリティ修正が提供されないため、今後見つかる脆弱性も修正されない。",
            remediation=f"{rt.product} をサポート中のバージョンへ移行する。",
            evidence={
                "kind": "eol_runtime",
                "product": rt.product,
                "version": rt.version,
                "cycle": status.cycle,
                "eol": status.eol.isoformat() if status.eol else None,
                "source": rt.source,
            },
            references=[f"{_EOL_REF}{rt.product}"],
        )

    def _os_finding(
        self, label: str, os_info: tuple[str, str, bool], eol: EolCatalog
    ) -> Finding | None:
        family, version, eosl = os_info
        product = _OS_PRODUCTS.get(family, family)
        status = eol.status(product, version, today=self._today)
        if not eosl and not (status and status.is_eol):
            return None
        return Finding.create(
            check_id=self.id,
            kind=f"eol_os:{family}|{version}",
            target=label,
            ipa_items=_IPA,
            severity=Severity.high,
            title=f"サポートが終了した OS（{family} {version}）をベースイメージに使用している",
            description="OS パッケージのセキュリティ修正が提供されない。",
            remediation="サポート中の OS バージョンのベースイメージへ移行する。",
            evidence={"kind": "eol_os", "os": f"{family} {version}", "eosl": eosl},
            references=[f"{_EOL_REF}{product}"],
        )
