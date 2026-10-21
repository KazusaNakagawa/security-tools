"""Access log analysis: coverage, daily anomalies, attack signatures (design §7.4)."""

from __future__ import annotations

import datetime as dt
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import cache
from importlib.resources import files

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from alertcheck.checks.files.log_parser import LogRecord

_RECENT_WINDOW = 7
_MIN_BASELINE = 14
_SUSPECT_EXT = re.compile(r"\.(php|phtml|jsp|jspx|asp|aspx|cgi|pl|py|sh)(\?|$)", re.IGNORECASE)


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    target: str  # path | ua
    label: str
    pattern: str

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, value: str) -> str:
        re.compile(value)
        return value


@dataclass(frozen=True)
class SignatureHit:
    id: str
    target: str
    label: str


@cache
def load_signatures() -> list[Signature]:
    raw = files("alertcheck.data").joinpath("attack_signatures.yaml").read_text(encoding="utf-8")
    return [Signature.model_validate(s) for s in yaml.safe_load(raw)["signatures"]]


@cache
def _compiled() -> list[tuple[Signature, re.Pattern[str]]]:
    return [(s, re.compile(s.pattern)) for s in load_signatures()]


def match_signatures(path: str, user_agent: str) -> list[SignatureHit]:
    hits = []
    for sig, pattern in _compiled():
        subject = user_agent if sig.target == "ua" else path
        if subject and pattern.search(subject):
            hits.append(SignatureHit(sig.id, sig.target, sig.label))
    return hits


@dataclass
class Coverage:
    oldest: dt.date | None
    newest: dt.date | None
    recent_span_days: int
    covers_30: bool
    covers_90: bool


def coverage_days(timestamps: list[dt.datetime | None], *, today: dt.date) -> Coverage:
    days = sorted({ts.date() for ts in timestamps if ts is not None})
    if not days:
        return Coverage(None, None, 0, False, False)
    oldest, newest = days[0], days[-1]
    span = (newest - oldest).days + 1
    # measured from today so a stale log does not count as recent coverage
    recent = (today - oldest).days + 1
    return Coverage(oldest, newest, span, recent >= 30, recent >= 90)


@dataclass(frozen=True)
class Anomaly:
    day: dt.date
    value: int
    mean: float
    z: float


def zscore_anomalies(daily: dict[dt.date, int], *, threshold: float) -> list[Anomaly]:
    if not daily:
        return []
    days = sorted(daily)
    recent = days[-_RECENT_WINDOW:]
    baseline = [daily[d] for d in days if d not in set(recent)]
    if len(baseline) < _MIN_BASELINE:
        return []
    mean = sum(baseline) / len(baseline)
    variance = sum((v - mean) ** 2 for v in baseline) / len(baseline)
    std = math.sqrt(variance)
    if std == 0:
        std = 1.0 if mean == 0 else mean * 0.01 or 1.0
    out = []
    for day in recent:
        z = (daily[day] - mean) / std
        if abs(z) >= threshold:
            out.append(Anomaly(day, daily[day], mean, z))
    return out


@dataclass
class LogStats:
    allowlist: list[re.Pattern[str]] | None
    daily_total: Counter = field(default_factory=Counter)
    daily_4xx: Counter = field(default_factory=Counter)
    daily_5xx: Counter = field(default_factory=Counter)
    signature_hits: dict[str, dict] = field(default_factory=dict)
    unexpected_200: Counter = field(default_factory=Counter)
    webshell_suspect: dict[str, set] = field(default_factory=lambda: defaultdict(set))
    ip_counter: Counter = field(default_factory=Counter)
    total: int = 0
    missing_ip: int = 0
    missing_user: int = 0
    timestamps: list = field(default_factory=list)

    def add(self, r: LogRecord) -> None:
        self.total += 1
        self.ip_counter[r.client_ip] += 1
        if not r.client_ip:
            self.missing_ip += 1
        if r.user is None:
            self.missing_user += 1
        if r.ts is not None:
            self.timestamps.append(r.ts)
            day = r.ts.date()
            self.daily_total[day] += 1
            if 400 <= r.status < 500:
                self.daily_4xx[day] += 1
            elif r.status >= 500:
                self.daily_5xx[day] += 1
        for hit in match_signatures(r.path, r.user_agent):
            entry = self.signature_hits.setdefault(
                hit.id,
                {
                    "label": hit.label,
                    "target": hit.target,
                    "count": 0,
                    "hits_200": 0,
                    "example": r.path[:200],
                },
            )
            entry["count"] += 1
            if r.status == 200:
                entry["hits_200"] += 1
        if r.status == 200:
            self._note_200(r)

    def _note_200(self, r: LogRecord) -> None:
        url = r.path
        if self.allowlist is not None:
            if not any(p.search(url) for p in self.allowlist):
                self.unexpected_200[url] += 1
        elif _SUSPECT_EXT.search(url):
            self.webshell_suspect[url].add(r.client_ip)

    def top_ip(self) -> list[tuple[str, int]]:
        return self.ip_counter.most_common(5)

    def webshell_candidates(self) -> list[str]:
        # dynamic files hit by only a few IPs look more like a shell than a shared page
        return [url for url, ips in self.webshell_suspect.items() if len(ips) <= 3]
