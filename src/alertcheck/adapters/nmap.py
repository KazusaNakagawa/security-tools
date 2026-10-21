"""nmap invocation (TCP connect scan of scope-validated addresses) and XML parsing."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


def args(target_file: str, *, ports: list[int], rate: float, excludes: list[str]) -> list[str]:
    argv = [
        "nmap",
        "-sT",  # TCP connect: no raw sockets or extra privileges
        "-sV",
        "-Pn",  # targets are explicitly listed; do not drop hosts that ignore pings
        "-n",  # no DNS: the scope guard already resolved and validated every address
        "--max-rate",
        str(max(1, int(rate))),
        "-p",
        ",".join(str(p) for p in sorted(set(ports))),
        "-iL",
        target_file,
        "-oX",
        "-",
    ]
    if excludes:
        argv += ["--exclude", ",".join(excludes)]
    return argv


@dataclass(frozen=True)
class OpenPort:
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""


@dataclass
class HostResult:
    address: str
    ports: list[OpenPort] = field(default_factory=list)


def parse(text: str) -> list[HostResult]:
    # nmap XML contains service banners as escaped text; it is produced by our own run
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ValueError(f"nmap output is not XML: {e}") from e
    hosts = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = next(
            (
                a.get("addr", "")
                for a in host.iter("address")
                if a.get("addrtype") in ("ipv4", "ipv6")
            ),
            "",
        )
        result = HostResult(address=address)
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            result.ports.append(
                OpenPort(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    service=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                )
            )
        hosts.append(result)
    return hosts
