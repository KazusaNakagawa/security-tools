"""Local vulnerability reference data: CISA KEV and endoflife.date cycles.

Both are read from the cache directory filled by `alertcheck db update`;
EOL data falls back to a snapshot bundled with the package so offline runs
still detect end-of-life runtimes.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_URL = "https://endoflife.date/api/{product}.json"
EOL_PRODUCTS = [
    "php",
    "nodejs",
    "python",
    "ruby",
    "go",
    "eclipse-temurin",
    "nginx",
    "apache-http-server",
    "tomcat",
    "openssl",
    "wordpress",
    "drupal",
    "joomla",
    "django",
    "laravel",
    "rails",
    "postgresql",
    "mysql",
    "redis",
    "alpine-linux",
    "debian",
    "ubuntu",
]


def cache_dir() -> Path:
    return Path(os.environ.get("ALERTCHECK_CACHE") or Path.home() / ".cache" / "alertcheck")


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


class KevCatalog:
    def __init__(self, data: dict[str, Any] | None) -> None:
        self.available = data is not None
        self.catalog_version = (data or {}).get("catalogVersion", "")
        self._ids: set[str] = set()
        self._products: dict[tuple[str, str], list[str]] = {}
        for v in (data or {}).get("vulnerabilities", []):
            cve = v.get("cveID", "").upper()
            self._ids.add(cve)
            key = (v.get("vendorProject", "").lower(), v.get("product", "").lower())
            self._products.setdefault(key, []).append(cve)

    @classmethod
    def load(cls, directory: Path | None = None) -> KevCatalog:
        path = (directory or cache_dir()) / "kev.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(None)
        return cls(data if isinstance(data, dict) else None)

    def contains(self, cve: str) -> bool:
        return cve.upper() in self._ids

    def product_cves(self, vendor: str, product: str) -> list[str]:
        return sorted(self._products.get((vendor.lower(), product.lower()), []))


@dataclass(frozen=True)
class EolStatus:
    product: str
    cycle: str
    eol: dt.date | None
    is_eol: bool


class EolCatalog:
    def __init__(self, products: dict[str, list[dict[str, Any]]], source: str) -> None:
        self._products = products
        self.source = source

    @classmethod
    def load(cls, directory: Path | None = None) -> EolCatalog:
        path = (directory or cache_dir()) / "eol.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(data["products"], "cache")
        except (OSError, ValueError, KeyError, TypeError):
            raw = files("alertcheck.data").joinpath("eol.json").read_text(encoding="utf-8")
            return cls(json.loads(raw)["products"], "bundled")

    def status(
        self, product: str, version: str, *, today: dt.date | None = None
    ) -> EolStatus | None:
        cycles = {str(c["cycle"]): c.get("eol") for c in self._products.get(product, [])}
        parts = version.strip().lstrip("vV").split(".")
        for n in (3, 2, 1):
            cycle = ".".join(parts[:n])
            if cycle in cycles:
                return _eol_status(product, cycle, cycles[cycle], today or dt.date.today())
        return None


def _eol_status(product: str, cycle: str, raw: Any, today: dt.date) -> EolStatus:
    if isinstance(raw, bool):
        return EolStatus(product, cycle, None, raw)
    try:
        date = dt.date.fromisoformat(str(raw))
    except ValueError:
        return EolStatus(product, cycle, None, False)
    return EolStatus(product, cycle, date, date <= today)


async def update_kev(client: httpx.AsyncClient, directory: Path | None = None) -> int:
    response = await client.get(KEV_URL, timeout=60)
    response.raise_for_status()
    try:
        data = response.json()
        count = len(data["vulnerabilities"])
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError(f"unexpected KEV feed format: {e}") from e
    _atomic_write((directory or cache_dir()) / "kev.json", json.dumps(data))
    return count


async def update_eol(
    client: httpx.AsyncClient, directory: Path | None = None, products: list[str] | None = None
) -> int:
    out: dict[str, Any] = {
        "source": "https://endoflife.date/api",
        "fetched_at": dt.date.today().isoformat(),
        "products": {},
    }
    for product in products or EOL_PRODUCTS:
        response = await client.get(EOL_URL.format(product=product), timeout=30)
        response.raise_for_status()
        out["products"][product] = [
            {"cycle": str(c["cycle"]), "eol": c.get("eol")} for c in response.json()
        ]
    _atomic_write((directory or cache_dir()) / "eol.json", json.dumps(out))
    return len(out["products"])
