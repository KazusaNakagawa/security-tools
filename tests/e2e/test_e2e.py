"""End-to-end: the Docker image scans the misconfigured target on an internal network.

Run with: ALERTCHECK_E2E=1 uv run pytest tests/e2e -q
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).parent
COMPOSE = ["docker", "compose", "-f", str(HERE / "compose.yaml")]

pytestmark = pytest.mark.skipif(
    not os.environ.get("ALERTCHECK_E2E"),
    reason="set ALERTCHECK_E2E=1 to run Docker end-to-end tests",
)


def compose(
    *args: str, env: dict[str, str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*COMPOSE, *args],
        env={**os.environ, **env},
        text=True,
        capture_output=True,
        check=check,
        timeout=900,
    )


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    workspace = tmp_path_factory.mktemp("e2e-workspace")
    workspace.chmod(0o777)  # the scanner runs as uid 10001
    shutil.copy(HERE / "scope.yaml", workspace / "scope.yaml")
    env = {"E2E_WORKSPACE": str(workspace)}
    compose("build", "scanner", env=env)
    compose("up", "-d", "--wait", "web", "app", "redis", env=env)
    try:
        # nuclei templates cannot be downloaded on the internal network
        scan = compose(
            "run", "--rm", "scanner", "scan", "--skip", "vuln.templates", env=env, check=False
        )
        compose("run", "--rm", "scanner", "report", "--format", "json", env=env, check=False)
        report_path = next((workspace / "out" / "runs").glob("*/report.json"))
        yield {
            "scan": scan,
            "data": json.loads(report_path.read_text(encoding="utf-8")),
            "network": json.loads(
                subprocess.run(
                    ["docker", "network", "inspect", "alertcheck-e2e_e2e"],
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout
            )[0],
            "web": json.loads(
                subprocess.run(
                    ["docker", "inspect", "alertcheck-e2e-web-1"],
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout
            )[0],
        }
    finally:
        compose("down", "-v", "--remove-orphans", env=env, check=False)


def findings(report, **match):
    return [
        f
        for f in report["data"]["findings"]
        if all(f.get(k) == v or f["evidence"].get(k) == v for k, v in match.items())
    ]


def items(report):
    return {i["ipa_item"]: i for i in report["data"]["items"]}


def test_scan_exits_with_critical(report):
    assert report["scan"].returncode == 2, report["scan"].stdout + report["scan"].stderr


def test_env_exposure_is_critical(report):
    env = findings(report, check_id="http.exposure", path=".env")
    assert env and env[0]["severity"] == "critical"
    assert env[0]["evidence"]["keys"] == ["APP_ENV", "DB_HOST", "DB_PASSWORD"]
    assert "e2e-not-a-real-secret" not in json.dumps(report["data"])


def test_missing_csp(report):
    assert findings(report, check_id="http.headers", kind="csp_missing")


def test_version_banner(report):
    assert findings(report, check_id="http.headers", kind="version_disclosure")


def test_stack_trace(report):
    trace = findings(report, check_id="http.errors", kind="stack_trace")
    assert trace and trace[0]["evidence"]["framework"] == "node"


def test_plain_http(report):
    assert findings(report, check_id="tls", kind="https_unavailable")


@pytest.mark.xfail(reason="API surface checks (Swagger) arrive with #3", strict=False)
def test_swagger_exposure(report):
    assert findings(report, check_id="api")


@pytest.mark.xfail(reason="port checks (Redis) arrive with #3", strict=False)
def test_redis_exposure(report):
    assert findings(report, check_id="ports")


def test_verdicts(report):
    verdicts = items(report)
    assert verdicts["A-1"]["verdict"] == "not_achieved"
    assert verdicts["D-2"]["verdict"] == "not_achieved"
    assert verdicts["A-6"]["verdict"] in ("partial", "not_achieved")
    assert report["data"]["score"]["critical"] >= 1


def test_target_is_isolated(report):
    assert report["network"]["Internal"] is True
    assert not any(report["web"]["NetworkSettings"]["Ports"].values() or [None])
