"""osv-scanner (v2) invocation and JSON parsing."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from alertcheck.adapters.vulns import VulnRecord, normalize_severity, severity_from_cvss

# osv-scanner exits 1 when vulnerabilities are found and 128 when no package sources exist
OK_EXIT_CODES = (0, 1, 128)


def args(path: str, *, offline: bool) -> list[str]:
    out = ["osv-scanner", "scan", "source", "--format", "json", "--recursive"]
    if offline:
        out.append("--offline")
    return [*out, path]


def _fixed_version(vuln: dict[str, Any], name: str) -> str | None:
    fixed = []
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("name") != name:
            continue
        for rng in affected.get("ranges") or []:
            fixed += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    return ", ".join(dict.fromkeys(fixed)) or None


def _group_score(groups: list[dict[str, Any]], vuln_id: str) -> float | None:
    for g in groups:
        if vuln_id in g.get("ids", []):
            try:
                return float(g.get("max_severity"))
            except (TypeError, ValueError):
                return None
    return None


def _relative(path: str, root: str | None) -> str:
    """Path of the scanned file relative to the scan root (the tool reports absolute paths)."""
    file = PurePosixPath(path)
    if root:
        try:
            return file.relative_to(PurePosixPath(root)).as_posix()
        except ValueError:
            pass
    return file.name


def parse(text: str, root: str | None = None) -> list[VulnRecord]:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"osv-scanner output is not JSON: {e}") from e
    records = []
    for result in data.get("results") or []:
        target = _relative((result.get("source") or {}).get("path", ""), root)
        for pkg in result.get("packages") or []:
            meta = pkg.get("package") or {}
            groups = pkg.get("groups") or []
            for v in pkg.get("vulnerabilities") or []:
                score = _group_score(groups, v["id"])
                severity = normalize_severity((v.get("database_specific") or {}).get("severity"))
                if severity == "unknown":
                    severity = severity_from_cvss(score)
                records.append(
                    VulnRecord(
                        id=v["id"],
                        package=meta.get("name", ""),
                        installed=meta.get("version", ""),
                        ecosystem=meta.get("ecosystem", ""),
                        target=target,
                        severity=severity,
                        cvss=score,
                        fixed=_fixed_version(v, meta.get("name", "")),
                        title=v.get("summary", ""),
                        url=f"https://osv.dev/vulnerability/{v['id']}",
                        aliases=tuple(v.get("aliases") or ()),
                        sources=frozenset({"osv"}),
                    )
                )
    return records
