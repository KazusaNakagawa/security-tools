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
