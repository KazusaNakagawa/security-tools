"""vuln.version: end-of-life software, KEV-listed products and exposed VPN appliances.

Design §7.3, IPA P1-4 / P2-1. Product versions come from response headers
and the HTML generator meta tag. Matching a banner version against
individual CVEs needs CPE data (NVD) and is out of scope here; instead the
check reports end-of-life versions (endoflife.date) and flags products that
have actively exploited vulnerabilities in CISA KEV so the version can be
verified.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from alertcheck.checks.network.base import HttpCheck, HttpTarget, InspectResult, fetch, probe_base
from alertcheck.core.context import Context
from alertcheck.core.models import Finding, Severity
from alertcheck.core.scope_guard import ScopeViolation
from alertcheck.vulndb import EolCatalog, KevCatalog

_V = r"(\d+\.\d+(?:\.\d+)?)"


@dataclass(frozen=True)
class Product:
    id: str  # endoflife.date slug (or a plain name when not tracked there)
    label: str
    pattern: re.Pattern[str]
    kev: tuple[str, str] | None  # (vendorProject, product) in CISA KEV


PRODUCTS = [
    Product(
        "apache-http-server",
        "Apache HTTP Server",
        re.compile(rf"Apache/{_V}"),
        ("Apache", "HTTP Server"),
    ),
    Product("nginx", "nginx", re.compile(rf"nginx/{_V}"), None),
    Product("php", "PHP", re.compile(rf"PHP/{_V}"), ("PHP", "PHP")),
    Product("openssl", "OpenSSL", re.compile(rf"OpenSSL/{_V}"), ("OpenSSL", "OpenSSL")),
    Product("tomcat", "Apache Tomcat", re.compile(rf"Tomcat/{_V}"), ("Apache", "Tomcat")),
    Product(
        "iis",
        "Microsoft IIS",
        re.compile(rf"Microsoft-IIS/{_V}"),
        ("Microsoft", "Internet Information Services (IIS)"),
    ),
    Product("wordpress", "WordPress", re.compile(rf"WordPress {_V}"), ("WordPress", "WordPress")),
    Product("drupal", "Drupal", re.compile(r"Drupal (\d+(?:\.\d+)*)"), ("Drupal", "Drupal Core")),
    Product("joomla", "Joomla!", re.compile(rf"Joomla! {_V}"), ("Joomla!", "Joomla!")),
]

_GENERATOR = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", re.IGNORECASE
)
_BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


@dataclass(frozen=True)
class VpnProbe:
    vendor: str
    product: str
    path: str
    pattern: re.Pattern[str]
    kev: tuple[str, str]


VPN_PROBES = [
    VpnProbe(
        "Fortinet",
        "FortiGate SSL-VPN",
        "remote/login",
        re.compile(r"fgt_lang|ftnt-fortinet|FortiGate", re.I),
        ("Fortinet", "FortiOS"),
    ),
    VpnProbe(
        "Ivanti",
        "Connect Secure",
        "dana-na/auth/url_default/welcome.cgi",
        re.compile(r"Ivanti|Pulse Secure|/dana-na/", re.I),
        ("Ivanti", "Connect Secure"),
    ),
    VpnProbe(
        "Palo Alto Networks",
        "GlobalProtect",
        "global-protect/login.esp",
        re.compile(r"GlobalProtect", re.I),
        ("Palo Alto Networks", "PAN-OS"),
    ),
    VpnProbe(
        "Cisco",
        "ASA / AnyConnect",
        "+CSCOE+/logon.html",
        re.compile(r"webvpn|CSCOE|AnyConnect", re.I),
        ("Cisco", "Adaptive Security Appliance (ASA)"),
    ),
    VpnProbe(
        "Citrix",
        "NetScaler Gateway",
        "vpn/index.html",
        re.compile(r"Citrix Gateway|NetScaler", re.I),
        ("Citrix", "NetScaler ADC"),
    ),
    VpnProbe(
        "SonicWall",
        "SMA / SSL-VPN",
        "cgi-bin/welcome",
        re.compile(r"SonicWall", re.I),
        ("SonicWall", "SMA100 Appliances"),
    ),
]

_FAILED = object()


class VulnVersionCheck(HttpCheck):
    id = "vuln.version"
    ipa_items = ["P1-4", "P2-1"]

    def __init__(self, cache: Path | None = None, today: dt.date | None = None) -> None:
        self._cache = cache
        self._today = today

    async def inspect(
        self, ctx: Context, target: HttpTarget, response: httpx.Response
    ) -> InspectResult:
        kev = KevCatalog.load(self._cache)
        eol = EolCatalog.load(self._cache)
        url = str(response.url)
        findings = self._banner_findings(url, response, kev, eol)

        base = probe_base(target.url)
        results = await asyncio.gather(*(self._probe(ctx, base, p, kev) for p in VPN_PROBES))
        findings += [r for r in results if isinstance(r, Finding)]
        failed = sum(1 for r in results if r is _FAILED)
        return InspectResult(findings=findings, probes=len(VPN_PROBES), failed=failed)

    def _banners(self, response: httpx.Response) -> list[tuple[str, str]]:
        found = [(h, response.headers[h]) for h in _BANNER_HEADERS if h in response.headers]
        match = _GENERATOR.search(response.text[:200_000])
        if match:
            found.append(("meta generator", match.group(1)))
        return found

    def _banner_findings(
        self, url: str, response: httpx.Response, kev: KevCatalog, eol: EolCatalog
    ) -> list[Finding]:
        findings = []
        seen: set[str] = set()
        for source, value in self._banners(response):
            for product in PRODUCTS:
                match = product.pattern.search(value)
                if not match or product.id in seen:
                    continue
                seen.add(product.id)
                version = match.group(1)
                evidence = {
                    "product": product.id,
                    "version": version,
                    "source": source,
                    "banner": value,
                }
                status = eol.status(product.id, version, today=self._today)
                if status and status.is_eol:
                    since = f"（{status.eol.isoformat()} に終了）" if status.eol else ""
                    findings.append(
                        self.finding(
                            kind="eol_software",
                            variant=product.id,
                            target=url,
                            severity=Severity.high,
                            ipa_items=["P1-4"],
                            title=f"サポートが終了した {product.label} {status.cycle} を公開している{since}",
                            description="セキュリティ修正が提供されず、既知・未知の脆弱性が修正されない。",
                            remediation=f"{product.label} をサポート中のバージョンへ更新し、バージョン表示も無効化する。",
                            evidence={**evidence, "cycle": status.cycle},
                            references=[f"https://endoflife.date/{product.id}"],
                        )
                    )
                cves = kev.product_cves(*product.kev) if product.kev else []
                if cves:
                    findings.append(
                        self.finding(
                            kind="kev_product",
                            variant=product.id,
                            target=url,
                            severity=Severity.medium,
                            ipa_items=["P1-4"],
                            title=f"{product.label} には悪用が確認された脆弱性がある（CISA KEV {len(cves)} 件）",
                            description=f"検出したバージョン {version} が影響を受けるか確認が必要。",
                            remediation="CISA KEV の該当 CVE を確認し、影響するバージョンなら直ちに更新する。",
                            evidence={**evidence, "kev_cves": cves[:20]},
                            references=[
                                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                            ],
                        )
                    )
        return findings

    async def _probe(
        self, ctx: Context, base: str, probe: VpnProbe, kev: KevCatalog
    ) -> Finding | object | None:
        url = urljoin(base, probe.path)
        try:
            resp = await fetch(ctx, url, max_body=64 * 1024)
        except ScopeViolation:
            return None
        except httpx.HTTPError:
            return _FAILED
        same_origin = urlsplit(str(resp.url)).netloc == urlsplit(url).netloc
        if resp.status_code != 200 or not same_origin:
            return None
        if not probe.pattern.search(resp.text) and not probe.pattern.search(str(resp.headers)):
            return None
        cves = kev.product_cves(*probe.kev)
        return self.finding(
            kind="vpn_appliance",
            variant=probe.vendor,
            target=url,
            severity=Severity.medium,
            ipa_items=["P2-1", "P1-4"],
            title=f"インターネットに公開された VPN 機器を検出（{probe.vendor} {probe.product}）",
            description=(
                "VPN 機器は不正アクセスの侵入口として悪用が相次いでいる。"
                "外部サービス台帳への登録、ファームウェアの更新状況、ログイン履歴の確認が必要。"
            ),
            remediation="最新のファームウェアを適用し、多要素認証を有効化し、管理画面を外部に公開しない。ログで不審な接続を確認する。",
            evidence={
                "vendor": probe.vendor,
                "product": probe.product,
                "url": url,
                "kev_cves": cves[:20],
            },
            references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
        )
