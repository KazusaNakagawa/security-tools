import pytest
import yaml
from typer.testing import CliRunner

from alertcheck.cli import app

runner = CliRunner()


def invoke(*args):
    return runner.invoke(app, list(args), catch_exceptions=False)


class TestInit:
    def test_creates_skeleton(self, tmp_path):
        result = invoke("init", "--workspace", str(tmp_path))
        assert result.exit_code == 0, result.output
        assert (tmp_path / "scope.yaml").is_file()
        assert (tmp_path / "questionnaire.yaml").is_file()
        for d in ["inputs/logs", "inputs/accounts", "inputs/hr", "inputs/repos", "out"]:
            assert (tmp_path / d).is_dir(), d

    def test_generated_scope_is_valid_and_unauthorized(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        data = yaml.safe_load((tmp_path / "scope.yaml").read_text())
        assert data["authorization"]["confirmed"] is False
        assert invoke("validate", "--workspace", str(tmp_path)).exit_code == 0

    def test_does_not_overwrite_without_force(self, tmp_path):
        (tmp_path / "scope.yaml").write_text("organization: Mine\n")
        result = invoke("init", "--workspace", str(tmp_path))
        assert result.exit_code == 0
        assert (tmp_path / "scope.yaml").read_text() == "organization: Mine\n"
        assert "skip" in result.output

    def test_force_overwrites(self, tmp_path):
        (tmp_path / "scope.yaml").write_text("organization: Mine\n")
        invoke("init", "--workspace", str(tmp_path), "--force")
        assert "Mine" not in (tmp_path / "scope.yaml").read_text()


class TestValidate:
    def test_invalid_scope_exits_3_with_readable_error(self, tmp_path):
        (tmp_path / "scope.yaml").write_text(
            "organization: X\nauthorization: {confirmed: true}\ntargets: {hosts: [999.1.1.1]}\n"
        )
        result = invoke("validate", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "authorization" in result.output
        assert "targets.hosts" in result.output
        assert "Traceback" not in result.output

    def test_missing_scope_exits_3(self, tmp_path):
        result = invoke("validate", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "alertcheck init" in result.output

    def test_valid_scope_prints_plan(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("validate", "--workspace", str(tmp_path))
        assert result.exit_code == 0
        assert "authorization.confirmed is false" in result.output
        assert "Unverified IPA items" in result.output
        assert "P1-2" in result.output

    def test_invalid_answers_exit_3(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        (tmp_path / "questionnaire.yaml").write_text("answers: {q_a2_mfa: {value: maybe}}\n")
        result = invoke("validate", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "q_a2_mfa" in result.output

    def test_missing_configured_input_exits_3(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        scope = tmp_path / "scope.yaml"
        scope.write_text(scope.read_text() + "\n# appended\n")
        data = yaml.safe_load(scope.read_text())
        data["inputs"] = {"roster": "inputs/hr/roster.csv"}
        scope.write_text(yaml.safe_dump(data, allow_unicode=True))
        result = invoke("validate", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "inputs/hr/roster.csv" in result.output


class TestScan:
    def test_scan_without_checks_exits_0(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("scan", "--workspace", str(tmp_path))
        assert result.exit_code == 0, result.output
        assert "0 finding" in result.output

    def test_scan_invalid_scope_exits_3(self, tmp_path):
        (tmp_path / "scope.yaml").write_text("organization: [\n")
        assert invoke("scan", "--workspace", str(tmp_path)).exit_code == 3


class TestStubs:
    def test_unimplemented_commands_exit_3(self, tmp_path):
        for args in (["diff", "a", "b"], ["serve"]):
            result = invoke(*args)
            assert result.exit_code == 3, args
            assert "not implemented" in result.output


class FailingCheck:
    id, group, requires, active, ipa_items = "boom", "files", [], False, ["A-1"]

    def plan(self, ctx):
        from alertcheck.core.models import Coverage

        return [Coverage(check_id=self.id, target="*", status="executed")]

    async def run(self, ctx):
        raise RuntimeError("kaboom")


class CyclicA:
    id, group, requires, active, ipa_items = "a", "files", ["b"], False, ["A-1"]


class CyclicB:
    id, group, requires, active, ipa_items = "b", "files", ["a"], False, ["A-1"]


def patch_registry(monkeypatch, *checks):
    from alertcheck.core.registry import Registry

    def factory(cls=None):
        reg = Registry()
        for c in checks:
            reg.register(c)
        return reg

    monkeypatch.setattr("alertcheck.cli.Registry.from_entry_points", staticmethod(factory))


class TestExecutionErrors:
    def test_scan_exits_3_when_a_check_errors(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FailingCheck())
        result = invoke("scan", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "kaboom" in result.output

    def test_scan_exits_3_on_dependency_cycle(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, CyclicA(), CyclicB())
        result = invoke("scan", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "cycle" in result.output

    def test_validate_exits_3_when_a_plan_errors(self, tmp_path, monkeypatch):
        class BrokenPlan(FailingCheck):
            def plan(self, ctx):
                raise ValueError("bad plan")

        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, BrokenPlan())
        result = invoke("validate", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "bad plan" in result.output


def test_init_writes_atomically(tmp_path, monkeypatch):
    import os

    calls = []
    real_replace = os.replace

    def spy(src, dst):
        calls.append((str(src), str(dst)))
        return real_replace(src, dst)

    monkeypatch.setattr("alertcheck.cli.os.replace", spy)
    invoke("init", "--workspace", str(tmp_path))
    assert {os.path.basename(d) for _, d in calls} == {"scope.yaml", "questionnaire.yaml"}
    assert not list(tmp_path.glob("*.tmp"))


class FindingCheck:
    id, group, requires, active, ipa_items = "demo", "files", [], False, ["A-1"]

    def plan(self, ctx):
        from alertcheck.core.models import Coverage

        return [Coverage(check_id=self.id, target="*", status="executed")]

    async def run(self, ctx):
        from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

        def make(kind, sev, title, target):
            return Finding.create(
                check_id=self.id,
                kind=kind,
                target=target,
                ipa_items=["A-1"],
                severity=sev,
                title=title,
                description="d",
                remediation=f"fix {kind}",
                evidence={"note": "yamada@example.co.jp"},
            )

        return CheckResult(
            findings=[
                make("low1", Severity.low, "低い問題", "https://a.example/x"),
                make("crit", Severity.critical, "重大な問題", "https://a.example/.env"),
                make("med", Severity.medium, "中程度の問題", "https://a.example/"),
            ],
            coverage=[Coverage(check_id=self.id, target="*", status="executed")],
        )


class TestScanOutput:
    def test_findings_are_listed_by_severity(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FindingCheck())
        result = invoke("scan", "--workspace", str(tmp_path))
        assert result.exit_code == 2
        out = result.output
        assert out.index("重大な問題") < out.index("中程度の問題") < out.index("低い問題")
        assert "https://a.example/.env" in out
        assert "fix crit" in out

    def test_findings_json_is_written(self, tmp_path, monkeypatch):
        import json

        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FindingCheck())
        result = invoke("scan", "--workspace", str(tmp_path))
        path = next((tmp_path / "out" / "runs").glob("*/findings.json"))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["run"]["id"] in result.output
        assert [f["severity"] for f in data["findings"]] == ["critical", "medium", "low"]
        assert data["findings"][0]["evidence"]["note"] == "y***@example.co.jp"
        assert {c["status"] for c in data["coverage"]} == {"executed"}
        assert str(path) in result.output

    def test_no_findings_message(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("scan", "--workspace", str(tmp_path))
        assert "0 finding" in result.output
        assert next((tmp_path / "out" / "runs").glob("*/findings.json")).is_file()


def test_validate_shows_check_targets(tmp_path, monkeypatch):
    from alertcheck.core.models import Coverage

    class TwoTargets(FindingCheck):
        def plan(self, ctx):
            return [
                Coverage(check_id=self.id, target="https://a.example/", status="executed"),
                Coverage(check_id=self.id, target="https://b.example/", status="executed"),
            ]

    invoke("init", "--workspace", str(tmp_path))
    patch_registry(monkeypatch, TwoTargets())
    out = invoke("validate", "--workspace", str(tmp_path)).output
    assert "demo https://a.example/" in out
    assert "demo https://b.example/" in out


class TestDbUpdate:
    def _mock_feeds(self, respx_mock, kev_status=200):
        from pathlib import Path

        kev = (Path(__file__).parents[1] / "fixtures" / "tools" / "kev.json").read_text()
        respx_mock.get(url__regex=r"https://www\.cisa\.gov/.*").mock(
            return_value=__import__("httpx").Response(kev_status, text=kev)
        )
        respx_mock.get(url__regex=r"https://endoflife\.date/api/.*").mock(
            return_value=__import__("httpx").Response(200, json=[{"cycle": "1", "eol": False}])
        )

    def test_updates_cache_and_reports_missing_tools(self, tmp_path, monkeypatch, respx_mock):
        from alertcheck.adapters.process import ToolNotFound

        async def no_tools(argv, *, timeout, ok_codes=(0,)):
            raise ToolNotFound(f"{argv[0]} not installed")

        monkeypatch.setenv("ALERTCHECK_CACHE", str(tmp_path))
        monkeypatch.setattr("alertcheck.cli.run_tool", no_tools)
        self._mock_feeds(respx_mock)
        result = invoke("db", "update")
        assert result.exit_code == 0, result.output
        assert (tmp_path / "kev.json").is_file()
        assert (tmp_path / "eol.json").is_file()
        assert "kev" in result.output and "4 entries" in result.output
        assert "trivy" in result.output and "not installed" in result.output

    def test_installed_tools_are_updated(self, tmp_path, monkeypatch, respx_mock):
        calls = []

        async def tools(argv, *, timeout, ok_codes=(0,)):
            calls.append(argv)
            return ""

        monkeypatch.setenv("ALERTCHECK_CACHE", str(tmp_path))
        monkeypatch.setattr("alertcheck.cli.run_tool", tools)
        self._mock_feeds(respx_mock)
        assert invoke("db", "update").exit_code == 0
        names = [c[0] for c in calls]
        assert names == ["trivy", "osv-scanner", "nuclei"]
        assert "--download-db-only" in calls[0]

    def test_feed_failure_exits_3(self, tmp_path, monkeypatch, respx_mock):
        async def tools(argv, *, timeout, ok_codes=(0,)):
            return ""

        monkeypatch.setenv("ALERTCHECK_CACHE", str(tmp_path))
        monkeypatch.setattr("alertcheck.cli.run_tool", tools)
        self._mock_feeds(respx_mock, kev_status=503)
        result = invoke("db", "update")
        assert result.exit_code == 3
        assert "kev" in result.output and "fail" in result.output


def test_db_update_tool_failure_exits_3(tmp_path, monkeypatch, respx_mock):
    from alertcheck.adapters.process import ToolFailed, ToolNotFound

    async def tools(argv, *, timeout, ok_codes=(0,)):
        if argv[0] == "trivy":
            raise ToolFailed("trivy exited 1: network unreachable")
        raise ToolNotFound(f"{argv[0]} not installed")

    monkeypatch.setenv("ALERTCHECK_CACHE", str(tmp_path))
    monkeypatch.setattr("alertcheck.cli.run_tool", tools)
    TestDbUpdate()._mock_feeds(respx_mock)
    result = invoke("db", "update")
    assert result.exit_code == 3
    assert "fail  trivy" in result.output
    assert "skip  nuclei" in result.output  # not installed is not a failure


class TestJudgedScan:
    def test_scan_judges_and_persists(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FindingCheck())
        result = invoke("scan", "--workspace", str(tmp_path))
        out = result.output
        assert "達成率" in out
        assert "critical" in out.splitlines()[0] or "警告" in out  # critical banner first
        run_id = next(
            line.split()[1].rstrip(":") for line in out.splitlines() if line.startswith("Run ")
        )

        from alertcheck.storage.sqlite import SqliteResultStore

        stored = SqliteResultStore(tmp_path / "out" / "alertcheck.db").get_run(run_id)
        assert stored is not None
        assert len(stored.items) == 27
        assert stored.score is not None
        a1 = next(i for i in stored.items if i.ipa_item == "A-1")
        assert a1.verdict == "not_achieved"  # critical finding on A-1

    def test_findings_json_includes_verdicts(self, tmp_path, monkeypatch):
        import json

        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FindingCheck())
        invoke("scan", "--workspace", str(tmp_path))
        data = json.loads(next((tmp_path / "out" / "runs").glob("*/findings.json")).read_text())
        assert len(data["items"]) == 27
        assert "overall" in data["score"]

    def test_mismatch_is_shown(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        (tmp_path / "questionnaire.yaml").write_text(
            "answers:\n  q_a1_exposure_reviewed: {value: done}\n"
        )
        patch_registry(monkeypatch, FindingCheck())
        out = invoke("scan", "--workspace", str(tmp_path)).output
        assert "食い違い" in out and "A-1" in out


class TestRuns:
    def test_list_and_show(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FindingCheck())
        out = invoke("scan", "--workspace", str(tmp_path)).output
        run_id = next(
            line.split()[1].rstrip(":") for line in out.splitlines() if line.startswith("Run ")
        )
        listing = invoke("runs", "--workspace", str(tmp_path))
        assert listing.exit_code == 0 and run_id in listing.output
        shown = invoke("runs", run_id, "--workspace", str(tmp_path))
        assert shown.exit_code == 0
        assert "A-1" in shown.output and "not_achieved" in shown.output
        assert "M-3" in shown.output

    def test_unknown_run(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("runs", "nope", "--workspace", str(tmp_path))
        assert result.exit_code == 3
        assert "nope" in result.output

    def test_no_runs_yet(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("runs", "--workspace", str(tmp_path))
        assert result.exit_code == 0
        assert "no runs" in result.output


class TestQuestionnaireCommands:
    def test_init_writes_template(self, tmp_path):
        result = invoke("questionnaire", "init", "--workspace", str(tmp_path))
        assert result.exit_code == 0
        assert "q_has_public_app" in (tmp_path / "questionnaire.yaml").read_text()

    def test_init_does_not_overwrite(self, tmp_path):
        (tmp_path / "questionnaire.yaml").write_text("answers: {}\n")
        result = invoke("questionnaire", "init", "--workspace", str(tmp_path))
        assert result.exit_code == 0
        assert (tmp_path / "questionnaire.yaml").read_text() == "answers: {}\n"

    def test_show(self, tmp_path):
        (tmp_path / "questionnaire.yaml").write_text("answers:\n  q_m1_leadership: {value: done}\n")
        out = invoke("questionnaire", "show", "--workspace", str(tmp_path)).output
        assert "q_m1_leadership" in out and "done" in out
        assert "1/25" in out

    def test_show_invalid_answers(self, tmp_path):
        (tmp_path / "questionnaire.yaml").write_text("answers: {q_m1_leadership: {value: maybe}}\n")
        assert invoke("questionnaire", "show", "--workspace", str(tmp_path)).exit_code == 3


def _scan(tmp_path, monkeypatch, *checks):
    invoke("init", "--workspace", str(tmp_path))
    patch_registry(monkeypatch, *checks)
    out = invoke("scan", "--workspace", str(tmp_path)).output
    return next(line.split()[1].rstrip(":") for line in out.splitlines() if line.startswith("Run "))


class TestReport:
    def test_latest_run_html_and_json(self, tmp_path, monkeypatch):
        import json

        run_id = _scan(tmp_path, monkeypatch, FindingCheck())
        result = invoke("report", "--workspace", str(tmp_path))
        run_dir = tmp_path / "out" / "runs" / run_id
        html = (run_dir / "report.html").read_text(encoding="utf-8")
        data = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
        assert (
            "経営サマリー" in html and "組織名を記入" in html
        )  # scope snapshot from init template
        assert data["run"]["id"] == run_id
        assert str(run_dir / "report.html") in result.output
        assert result.exit_code == 2  # the stored run has a critical finding

    def test_specific_run_and_format(self, tmp_path, monkeypatch):
        run_id = _scan(tmp_path, monkeypatch, FindingCheck())
        result = invoke("report", "--workspace", str(tmp_path), "--run", run_id, "--format", "json")
        run_dir = tmp_path / "out" / "runs" / run_id
        assert (run_dir / "report.json").is_file()
        assert not (run_dir / "report.html").exists()
        assert result.exit_code == 2

    def test_unknown_format(self, tmp_path, monkeypatch):
        _scan(tmp_path, monkeypatch, FindingCheck())
        result = invoke("report", "--workspace", str(tmp_path), "--format", "pdf")
        assert result.exit_code == 3 and "pdf" in result.output

    def test_unknown_run(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("report", "--workspace", str(tmp_path), "--run", "nope")
        assert result.exit_code == 3 and "nope" in result.output

    def test_no_runs(self, tmp_path):
        invoke("init", "--workspace", str(tmp_path))
        result = invoke("report", "--workspace", str(tmp_path))
        assert result.exit_code == 3 and "alertcheck scan" in result.output

    def test_redact_ips(self, tmp_path, monkeypatch):
        class IpCheck(FindingCheck):
            async def run(self, ctx):
                from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

                f = Finding.create(
                    check_id=self.id,
                    kind="ip",
                    target="https://203.0.113.10/",
                    ipa_items=["A-1"],
                    severity=Severity.low,
                    title="t",
                    description="d",
                    remediation="r",
                )
                return CheckResult(
                    findings=[f],
                    coverage=[Coverage(check_id=self.id, target="*", status="executed")],
                )

        run_id = _scan(tmp_path, monkeypatch, IpCheck())
        invoke("report", "--workspace", str(tmp_path), "--redact-ips")
        html = (tmp_path / "out" / "runs" / run_id / "report.html").read_text(encoding="utf-8")
        assert "203.0.113.10" not in html


class TestExitCodes:
    @pytest.mark.parametrize(
        "severity,code", [("critical", 2), ("high", 1), ("medium", 0), ("info", 0)]
    )
    def test_scan_and_report_exit_codes(self, tmp_path, monkeypatch, severity, code):
        class SevCheck(FindingCheck):
            async def run(self, ctx):
                from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

                f = Finding.create(
                    check_id=self.id,
                    kind="k",
                    target="t",
                    ipa_items=["A-6"],
                    severity=Severity(severity),
                    title="t",
                    description="d",
                    remediation="r",
                )
                return CheckResult(
                    findings=[f],
                    coverage=[Coverage(check_id=self.id, target="*", status="executed")],
                )

        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, SevCheck())
        assert invoke("scan", "--workspace", str(tmp_path)).exit_code == code
        assert invoke("report", "--workspace", str(tmp_path)).exit_code == code

    def test_execution_error_wins(self, tmp_path, monkeypatch):
        invoke("init", "--workspace", str(tmp_path))
        patch_registry(monkeypatch, FailingCheck(), FindingCheck())
        assert invoke("scan", "--workspace", str(tmp_path)).exit_code == 3
        assert invoke("report", "--workspace", str(tmp_path)).exit_code == 3
