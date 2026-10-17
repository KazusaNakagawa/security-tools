import datetime as dt
import json
from pathlib import Path

import httpx
import pytest
import respx

from alertcheck.vulndb import EolCatalog, KevCatalog, update_eol, update_kev

FIX = Path(__file__).parents[2] / "fixtures" / "tools"
TODAY = dt.date(2026, 10, 17)


class TestKev:
    def test_load_from_cache(self, tmp_path):
        (tmp_path / "kev.json").write_text((FIX / "kev.json").read_text())
        kev = KevCatalog.load(tmp_path)
        assert kev.available
        assert kev.contains("cve-2021-3129")
        assert not kev.contains("CVE-2000-0001")
        assert kev.catalog_version == "2026.10.16"

    def test_products(self, tmp_path):
        (tmp_path / "kev.json").write_text((FIX / "kev.json").read_text())
        kev = KevCatalog.load(tmp_path)
        assert kev.product_cves("apache", "http server") == ["CVE-2021-41773"]
        assert kev.product_cves("fortinet", "fortios") == ["CVE-2024-21762"]
        assert kev.product_cves("nobody", "nothing") == []

    def test_missing_cache(self, tmp_path):
        kev = KevCatalog.load(tmp_path)
        assert not kev.available
        assert not kev.contains("CVE-2021-3129")

    def test_corrupt_cache(self, tmp_path):
        (tmp_path / "kev.json").write_text("{not json")
        assert not KevCatalog.load(tmp_path).available


class TestEol:
    def test_bundled_snapshot_is_used_without_cache(self, tmp_path):
        eol = EolCatalog.load(tmp_path)
        status = eol.status("php", "7.4.33", today=TODAY)
        assert status is not None and status.is_eol
        assert status.cycle == "7.4"
        assert eol.source == "bundled"

    @pytest.mark.parametrize(
        "product,version,expected",
        [
            ("php", "8.3.1", False),
            ("nodejs", "14.21.3", True),
            ("python", "3.8.18", True),
            ("nginx", "1.18.0", True),
            ("debian", "10.13", True),
        ],
    )
    def test_cycles(self, tmp_path, product, version, expected):
        status = EolCatalog.load(tmp_path).status(product, version, today=TODAY)
        assert status is not None and status.is_eol is expected

    def test_unknown_product_or_cycle(self, tmp_path):
        eol = EolCatalog.load(tmp_path)
        assert eol.status("cobol", "1.0", today=TODAY) is None
        assert eol.status("php", "99.1", today=TODAY) is None

    def test_boolean_eol_values(self, tmp_path):
        data = {"products": {"x": [{"cycle": "1", "eol": True}, {"cycle": "2", "eol": False}]}}
        (tmp_path / "eol.json").write_text(json.dumps(data))
        eol = EolCatalog.load(tmp_path)
        assert eol.source == "cache"
        assert eol.status("x", "1.2", today=TODAY).is_eol
        assert not eol.status("x", "2.0", today=TODAY).is_eol

    def test_eol_today_counts_as_eol(self, tmp_path):
        data = {"products": {"x": [{"cycle": "1", "eol": "2026-10-17"}]}}
        (tmp_path / "eol.json").write_text(json.dumps(data))
        assert EolCatalog.load(tmp_path).status("x", "1.0", today=TODAY).is_eol


class TestUpdate:
    @respx.mock
    async def test_update_kev_writes_cache(self, tmp_path):
        respx.get(url__regex=r"https://www\.cisa\.gov/.*known_exploited.*").mock(
            return_value=httpx.Response(200, text=(FIX / "kev.json").read_text())
        )
        async with httpx.AsyncClient() as client:
            count = await update_kev(client, tmp_path)
        assert count == 4
        assert KevCatalog.load(tmp_path).available

    @respx.mock
    async def test_update_kev_rejects_garbage(self, tmp_path):
        respx.get(url__regex=r"https://www\.cisa\.gov/.*").mock(
            return_value=httpx.Response(200, text="<html>")
        )
        async with httpx.AsyncClient() as client:
            with pytest.raises(ValueError):
                await update_kev(client, tmp_path)
        assert not (tmp_path / "kev.json").exists()

    @respx.mock
    async def test_update_eol(self, tmp_path):
        respx.get(url__regex=r"https://endoflife\.date/api/.*\.json").mock(
            return_value=httpx.Response(200, json=[{"cycle": "7.4", "eol": "2022-11-28"}])
        )
        async with httpx.AsyncClient() as client:
            await update_eol(client, tmp_path, products=["php"])
        eol = EolCatalog.load(tmp_path)
        assert eol.source == "cache"
        assert eol.status("php", "7.4.1", today=TODAY).is_eol
