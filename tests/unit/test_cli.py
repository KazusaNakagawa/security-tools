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
        for args in (["report"], ["diff", "a", "b"], ["db", "update"], ["serve"]):
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
