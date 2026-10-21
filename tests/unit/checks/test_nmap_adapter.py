from pathlib import Path

import pytest

from alertcheck.adapters import nmap

FIX = Path(__file__).parents[2] / "fixtures" / "tools"


def test_parse_open_ports_only():
    hosts = nmap.parse((FIX / "nmap.xml").read_text())
    assert [h.address for h in hosts] == ["93.184.216.34"]
    ports = {(p.port, p.service) for p in hosts[0].ports}
    assert ports == {(22, "ssh"), (80, "http"), (443, "https"), (6379, "redis"), (23, "telnet")}
    redis = next(p for p in hosts[0].ports if p.port == 6379)
    assert redis.product == "Redis key-value store" and redis.version == "7.2.4"


def test_parse_rejects_non_xml():
    with pytest.raises(ValueError):
        nmap.parse("not xml")


def test_args_are_connect_scan_without_dns():
    argv = nmap.args("/tmp/t.txt", ports=[22, 6379], rate=5, excludes=["203.0.113.5"])
    assert argv[0] == "nmap"
    assert "-sT" in argv and "-sS" not in argv
    assert "-n" in argv  # no DNS: addresses were validated by the scope guard
    assert argv[argv.index("-iL") + 1] == "/tmp/t.txt"
    assert argv[argv.index("-p") + 1] == "22,6379"
    assert argv[argv.index("--max-rate") + 1] == "5"
    assert argv[argv.index("--exclude") + 1] == "203.0.113.5"
    assert argv[argv.index("-oX") + 1] == "-"


def test_args_without_excludes():
    assert "--exclude" not in nmap.args("/tmp/t.txt", ports=[22], rate=1, excludes=[])
