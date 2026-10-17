"""Thin wrapper around sslyze that returns a plain result object.

sslyze opens its own sockets, so callers must pass the address the Scope
Guard validated; the scan then never resolves the name itself.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from sslyze import (
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

_PROTOCOLS = {
    "SSLv2": ScanCommand.SSL_2_0_CIPHER_SUITES,
    "SSLv3": ScanCommand.SSL_3_0_CIPHER_SUITES,
    "TLSv1.0": ScanCommand.TLS_1_0_CIPHER_SUITES,
    "TLSv1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
    "TLSv1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
    "TLSv1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
}
_WEAK_MARKERS = ("RC4", "3DES", "DES_CBC", "_DES_", "NULL", "EXPORT", "anon", "MD5")


@dataclass
class TlsScanResult:
    host: str
    port: int
    error: str | None = None
    accepted_protocols: set[str] = field(default_factory=set)
    weak_ciphers: list[str] = field(default_factory=list)
    cert_not_after: datetime | None = None
    hostname_matches: bool | None = None
    trusted: bool | None = None


def hostname_matches(cert: x509.Certificate, hostname: str) -> bool:
    """RFC 6125-style match against SAN (falling back to CN), one-label wildcards only."""
    hostname = hostname.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        if ip is not None:
            return ip in san.get_values_for_type(x509.IPAddress)
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    for name in names:
        name = str(name).lower().rstrip(".")
        if name == hostname:
            return True
        if (
            name.startswith("*.")
            and hostname.count(".") == name.count(".")
            and hostname.endswith(name[1:])
        ):
            return True
    return False


def scan(host: str, port: int, ip_address: str, *, concurrency: int = 4) -> TlsScanResult:
    location = ServerNetworkLocation(hostname=host, port=port, ip_address=ip_address)
    request = ServerScanRequest(
        server_location=location,
        scan_commands={*_PROTOCOLS.values(), ScanCommand.CERTIFICATE_INFO},
    )
    scanner = Scanner(per_server_concurrent_connections_limit=concurrency)
    scanner.queue_scans([request])
    result = TlsScanResult(host=host, port=port)
    for server in scanner.get_results():
        if server.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            result.error = str(server.connectivity_error_trace or "no TLS connectivity")
            return result
        scan_result = server.scan_result
        assert scan_result is not None
        for name, command in _PROTOCOLS.items():
            attempt = getattr(scan_result, command.value)
            if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
                continue
            accepted = attempt.result.accepted_cipher_suites
            if accepted:
                result.accepted_protocols.add(name)
            if name not in ("SSLv2", "SSLv3"):  # SSL itself is reported as a whole
                result.weak_ciphers += [
                    c.cipher_suite.name
                    for c in accepted
                    if any(m in c.cipher_suite.name for m in _WEAK_MARKERS)
                ]
        cert_attempt = scan_result.certificate_info
        if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            deployments = cert_attempt.result.certificate_deployments
            if deployments:
                deployment = deployments[0]
                leaf = deployment.received_certificate_chain[0]
                result.cert_not_after = leaf.not_valid_after_utc
                result.hostname_matches = hostname_matches(leaf, host)
                result.trusted = any(
                    p.was_validation_successful for p in deployment.path_validation_results
                )
    result.weak_ciphers = sorted(set(result.weak_ciphers))
    return result
