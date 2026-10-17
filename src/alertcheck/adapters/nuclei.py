"""nuclei invocation (safe template subset) and JSONL parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass

TAGS = "exposure,misconfig,tech"
EXCLUDED_TAGS = "intrusive,dos,fuzz,bruteforce"


def args(list_file: str, *, rps: float, concurrency: int, timeout: float) -> list[str]:
    return [
        "nuclei",
        "-list",
        list_file,
        "-tags",
        TAGS,
        "-etags",
        EXCLUDED_TAGS,
        "-rl",
        str(max(1, int(rps))),
        "-c",
        str(concurrency),
        "-timeout",
        str(int(timeout)),
        "-ni",  # no interactsh: never send out-of-band callbacks to a third-party server
        "-dr",  # do not follow redirects (targets were scope-checked, redirect targets were not)
        "-omit-raw",  # keep request/response bodies (and any secrets) out of the output
        "-disable-update-check",
        "-no-color",
        "-silent",
        "-jsonl",
    ]


@dataclass(frozen=True)
class NucleiHit:
    template_id: str
    name: str
    severity: str
    tags: tuple[str, ...]
    cves: tuple[str, ...]
    host: str
    matched_at: str
    matcher: str | None


def parse(text: str) -> list[NucleiHit]:
    hits = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        info = row.get("info") or {}
        cve_ids = (info.get("classification") or {}).get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        hits.append(
            NucleiHit(
                template_id=row.get("template-id", ""),
                name=info.get("name", ""),
                severity=(info.get("severity") or "info").lower(),
                tags=tuple(info.get("tags") or ()),
                cves=tuple(c.upper() for c in cve_ids if c),
                host=row.get("host", ""),
                matched_at=row.get("matched-at", row.get("host", "")),
                matcher=row.get("matcher-name"),
            )
        )
    return hits
