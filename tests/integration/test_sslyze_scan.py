"""Runs sslyze against a local TLS server with a self-signed certificate."""

import datetime as dt
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from alertcheck.adapters.sslyze_scan import hostname_matches, scan


def make_cert(tmp_path, names, days=365):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, cert_path, key_path


@pytest.fixture
def tls_server(tmp_path):
    import socket

    _, cert_path, key_path = make_cert(tmp_path, ["localhost"], days=10)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(1)
                    tls.recv(1024)
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield sock.getsockname()[1]
    stop.set()
    thread.join(timeout=2)
    sock.close()


def test_scan_local_server(tls_server):
    result = scan("localhost", tls_server, "127.0.0.1")
    assert result.error is None
    assert "TLSv1.2" in result.accepted_protocols
    assert not {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"} & result.accepted_protocols
    assert result.hostname_matches is True
    assert result.trusted is False  # self-signed
    remaining = result.cert_not_after - dt.datetime.now(dt.UTC)
    assert dt.timedelta(days=9) < remaining <= dt.timedelta(days=10)


def test_scan_closed_port_reports_error():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    result = scan("localhost", port, "127.0.0.1")
    assert result.error


class TestHostnameMatches:
    def test_exact_and_wildcard(self, tmp_path):
        cert, _, _ = make_cert(tmp_path, ["example.co.jp", "*.example.co.jp"])
        assert hostname_matches(cert, "example.co.jp")
        assert hostname_matches(cert, "www.example.co.jp")
        assert not hostname_matches(cert, "a.b.example.co.jp")
        assert not hostname_matches(cert, "evil-example.co.jp")
        assert not hostname_matches(cert, "other.example")
