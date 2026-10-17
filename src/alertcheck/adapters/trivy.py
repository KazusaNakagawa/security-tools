"""trivy (filesystem / image) invocation and JSON parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass

from alertcheck.adapters.vulns import VulnRecord, normalize_severity

_COMMON = ["--scanners", "vuln", "--format", "json", "--quiet"]
_OFFLINE = ["--offline-scan", "--skip-db-update", "--skip-java-db-update"]


def fs_args(path: str, *, offline: bool) -> list[str]:
    return ["trivy", "fs", *_COMMON, *(_OFFLINE if offline else []), path]


def image_args(image: str, *, offline: bool) -> list[str]:
    return ["trivy", "image", *_COMMON, *(_OFFLINE if offline else []), image]


@dataclass
class TrivyReport:
    vulns: list[VulnRecord]
    os: tuple[str, str, bool] | None  # (family, version, end of service life)


def parse(text: str) -> TrivyReport:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"trivy output is not JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("trivy output is not a JSON object")

    os_meta = (data.get("Metadata") or {}).get("OS")
    os_info = None
    if os_meta and os_meta.get("Family"):
        os_info = (os_meta["Family"], str(os_meta.get("Name", "")), bool(os_meta.get("EOSL")))

    vulns = []
    for result in data.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            cvss = None
            for source in (v.get("CVSS") or {}).values():
                score = source.get("V3Score") or source.get("V2Score")
                if score is not None:
                    cvss = max(cvss or 0.0, float(score))
            vulns.append(
                VulnRecord(
                    id=v["VulnerabilityID"],
                    package=v.get("PkgName", ""),
                    installed=v.get("InstalledVersion", ""),
                    ecosystem=result.get("Type", ""),
                    target=result.get("Target", ""),
                    severity=normalize_severity(v.get("Severity")),
                    cvss=cvss,
                    fixed=v.get("FixedVersion") or None,
                    title=v.get("Title", ""),
                    url=v.get("PrimaryURL"),
                    sources=frozenset({"trivy"}),
                )
            )
    return TrivyReport(vulns=vulns, os=os_info)
