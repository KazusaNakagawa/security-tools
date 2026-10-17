"""alertcheck scan against a deliberately misconfigured local HTTP server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import yaml
from typer.testing import CliRunner

from alertcheck.cli import app


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            body = b"<html><body>shop</body></html>"
            self.send_response(200)
            self.send_header("Server", "Apache/2.4.49")
            self.send_header("Set-Cookie", "PHPSESSID=abc; Path=/")
        elif self.path == "/.env":
            body = b"DB_PASSWORD=s3cr3t\nAPP_KEY=xyz\n"
            self.send_response(200)
        elif "%27" in self.path:
            body = b'<pre>Traceback (most recent call last):\n  File "/app/x.py"</pre>'
            self.send_response(500)
        else:
            body = b"<html>not found</html>"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def test_scan_finds_misconfigurations(tmp_path, server):
    runner = CliRunner()
    assert runner.invoke(app, ["init", "-w", str(tmp_path)]).exit_code == 0
    scope = {
        "organization": "Test",
        "authorization": {"confirmed": True, "approver": "qa", "confirmed_at": "2026-10-17"},
        "targets": {"urls": [f"http://127.0.0.1:{server}/"]},
        "limits": {"rps_per_host": 100, "concurrency": 8},
    }
    (tmp_path / "scope.yaml").write_text(yaml.safe_dump(scope), encoding="utf-8")

    result = runner.invoke(app, ["scan", "-w", str(tmp_path)], catch_exceptions=False)

    assert result.exit_code == 2, result.output  # critical: exposed .env
    assert "critical" in result.output
    log = next((tmp_path / "out" / "runs").glob("*/requests.jsonl"))
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert {e["event"] for e in events} <= {"request", "response", "blocked", "error"}
    assert all("127.0.0.1" in e["url"] for e in events)
    assert "s3cr3t" not in log.read_text()
