from pathlib import Path

import pytest

from alertcheck.adapters import nuclei, osv, trivy
from alertcheck.adapters.vulns import merge_records

FIX = Path(__file__).parents[2] / "fixtures" / "tools"


def load(name):
    return (FIX / name).read_text(encoding="utf-8")


class TestTrivy:
    def test_fs_report(self):
        report = trivy.parse(load("trivy_fs.json"))
        assert report.os is None
        by_id = {r.id: r for r in report.vulns}
        ign = by_id["CVE-2021-3129"]
        assert (ign.package, ign.installed, ign.fixed, ign.ecosystem) == (
            "facade/ignition",
            "2.5.1",
            "2.5.2",
            "composer",
        )
        assert ign.severity == "critical" and ign.cvss == 9.8
        assert ign.target == "composer.lock"
        assert by_id["CVE-2022-29248"].fixed == "7.4.3, 6.5.6"
        assert by_id["CVE-2099-0001"].fixed is None
        assert {r.sources for r in report.vulns} == {frozenset({"trivy"})}

    def test_image_report_os_eol(self):
        report = trivy.parse(load("trivy_image.json"))
        assert report.os == ("debian", "10.13", True)
        assert report.vulns[0].ecosystem == "debian"

    def test_args(self):
        assert trivy.fs_args("/ws/repo", offline=False)[:4] == ["trivy", "fs", "--scanners", "vuln"]
        offline = trivy.fs_args("/ws/repo", offline=True)
        assert {"--offline-scan", "--skip-db-update", "--skip-java-db-update"} <= set(offline)
        assert trivy.image_args("img:1", offline=False)[:2] == ["trivy", "image"]

    @pytest.mark.parametrize("bad", ["", "{", "[]"])
    def test_invalid_json(self, bad):
        with pytest.raises(ValueError):
            trivy.parse(bad)


class TestOsv:
    def test_report(self):
        records = osv.parse(load("osv.json"))
        by_pkg = {r.package: r for r in records}
        guzzle = by_pkg["guzzlehttp/guzzle"]
        assert guzzle.id == "GHSA-f2wf-25xc-69c9"
        assert guzzle.aliases == ("CVE-2022-29248",)
        assert guzzle.fixed == "7.4.3"
        assert guzzle.cvss == 8.1
        assert guzzle.severity == "high"
        assert guzzle.target == "composer.lock"
        assert by_pkg["monolog/monolog"].fixed is None
        assert by_pkg["monolog/monolog"].severity == "low"

    def test_empty(self):
        assert osv.parse('{"results": []}') == []

    def test_args(self):
        args = osv.args("/ws/repo", offline=True)
        assert args[:3] == ["osv-scanner", "scan", "source"]
        assert "--offline" in args and "--format" in args


class TestMerge:
    def test_dedup_by_cve_across_tools(self):
        merged = merge_records(
            trivy.parse(load("trivy_fs.json")).vulns + osv.parse(load("osv.json"))
        )
        keys = sorted(r.key for r in merged)
        assert keys == ["CVE-2021-3129", "CVE-2022-29248", "CVE-2099-0001", "GHSA-xxxx-osv-only"]
        guzzle = next(r for r in merged if r.key == "CVE-2022-29248")
        assert guzzle.sources == frozenset({"trivy", "osv"})
        assert guzzle.fixed == "7.4.3, 6.5.6"  # keep the richer value
        assert guzzle.cvss == 8.1


class TestNuclei:
    def test_hits(self):
        hits = nuclei.parse(load("nuclei.jsonl"))
        assert [h.template_id for h in hits] == [
            "git-config",
            "CVE-2021-41773",
            "tech-detect",
            "http-missing-security-headers",
        ]
        cve = hits[1]
        assert cve.cves == ("CVE-2021-41773",)
        assert cve.severity == "high"
        assert cve.matched_at == "https://www.example.co.jp/cgi-bin/"
        assert hits[2].matcher == "nginx"

    def test_args_are_safe(self):
        args = nuclei.args("/tmp/targets.txt", rps=5, concurrency=4, timeout=10)
        for flag in ["-ni", "-dr", "-disable-update-check", "-jsonl", "-omit-raw"]:
            assert flag in args
        assert args[args.index("-etags") + 1] == "intrusive,dos,fuzz,bruteforce"
        assert args[args.index("-rl") + 1] == "5"
        assert "-list" in args and "/tmp/targets.txt" in args


class TestOsvPaths:
    def test_target_is_relative_to_scanned_root(self):
        text = load("osv.json").replace(
            "/ws/inputs/repos/shop/composer.lock", "/ws/inputs/repos/shop/apps/api/composer.lock"
        )
        records = osv.parse(text, root="/ws/inputs/repos/shop")
        assert {r.target for r in records} == {"apps/api/composer.lock"}

    def test_path_outside_root_falls_back_to_name(self):
        records = osv.parse(load("osv.json"), root="/elsewhere")
        assert {r.target for r in records} == {"composer.lock"}


def test_same_package_in_two_files_stays_separate():
    from dataclasses import replace

    base = trivy.parse(load("trivy_fs.json")).vulns[0]
    other = replace(base, target="apps/admin/composer.lock")
    merged = merge_records([base, other])
    assert sorted(r.target for r in merged) == ["apps/admin/composer.lock", "composer.lock"]
