"""Common vulnerability record produced by trivy / osv-scanner parsers."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ALIASES = {"moderate": "medium", "important": "high", "negligible": "low"}


def normalize_severity(value: str | None) -> str:
    value = (value or "unknown").strip().lower()
    value = _ALIASES.get(value, value)
    return value if value in SEVERITY_ORDER else "unknown"


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "unknown"


@dataclass(frozen=True)
class VulnRecord:
    id: str
    package: str
    installed: str
    ecosystem: str
    target: str
    severity: str = "unknown"
    cvss: float | None = None
    fixed: str | None = None
    title: str = ""
    url: str | None = None
    aliases: tuple[str, ...] = ()
    sources: frozenset[str] = field(default_factory=frozenset)

    @property
    def key(self) -> str:
        """CVE identifier when one is known, so the same issue from two tools merges."""
        for candidate in (self.id, *self.aliases):
            if candidate.upper().startswith("CVE-"):
                return candidate.upper()
        return self.id

    @property
    def cves(self) -> list[str]:
        return sorted({c.upper() for c in (self.id, *self.aliases) if c.upper().startswith("CVE-")})


def _richer(a: str | None, b: str | None) -> str | None:
    if not a:
        return b
    if not b:
        return a
    return a if len(a) >= len(b) else b


def merge_records(records: list[VulnRecord]) -> list[VulnRecord]:
    # the same issue reported by both tools for the same file merges; other files stay separate
    merged: dict[tuple[str, str, str, str], VulnRecord] = {}
    for r in records:
        k = (r.key, r.package, r.installed, r.target)
        cur = merged.get(k)
        if cur is None:
            merged[k] = r
            continue
        severity = max(cur.severity, r.severity, key=lambda s: SEVERITY_ORDER[s])
        cvss_values = [v for v in (cur.cvss, r.cvss) if v is not None]
        merged[k] = replace(
            cur,
            id=cur.key,
            severity=severity,
            cvss=max(cvss_values) if cvss_values else None,
            fixed=_richer(cur.fixed, r.fixed),
            title=cur.title or r.title,
            url=cur.url or r.url,
            aliases=tuple(sorted({*cur.aliases, *r.aliases, cur.id, r.id} - {cur.key})),
            sources=cur.sources | r.sources,
        )
    return list(merged.values())
