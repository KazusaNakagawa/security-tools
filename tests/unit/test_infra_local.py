import pytest

from alertcheck.config.scope import ConfigError
from alertcheck.core.models import RunResult
from alertcheck.infra.base import SecretNotFound
from alertcheck.infra.factory import build_infra
from alertcheck.infra.local import (
    EnvSecretProvider,
    InMemoryResultStore,
    LocalWorkspace,
    NullNotifier,
)


class TestLocalWorkspace:
    def test_open_and_glob_inputs(self, tmp_path):
        (tmp_path / "inputs" / "logs").mkdir(parents=True)
        (tmp_path / "inputs" / "logs" / "a.log").write_text("x")
        (tmp_path / "inputs" / "logs" / "b.log").write_text("y")
        ws = LocalWorkspace(tmp_path)
        assert ws.glob_inputs("inputs/logs/*.log") == ["inputs/logs/a.log", "inputs/logs/b.log"]
        with ws.open_input("inputs/logs/a.log") as f:
            assert f.read() == b"x"

    def test_glob_with_no_match_returns_empty(self, tmp_path):
        assert LocalWorkspace(tmp_path).glob_inputs("inputs/*.csv") == []

    @pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "inputs/../../x"])
    def test_paths_outside_workspace_are_rejected(self, tmp_path, path):
        ws = LocalWorkspace(tmp_path / "ws")
        (tmp_path / "ws").mkdir()
        with pytest.raises(PermissionError):
            ws.open_input(path)
        with pytest.raises(PermissionError):
            ws.glob_inputs(path)

    def test_write_output(self, tmp_path):
        ws = LocalWorkspace(tmp_path)
        written = ws.write_output("run1", "report.json", b"{}", "application/json")
        assert (tmp_path / "out" / "runs" / "run1" / "report.json").read_bytes() == b"{}"
        assert written.endswith("out/runs/run1/report.json")

    @pytest.mark.parametrize("name", ["../x", "a/b", ""])
    def test_write_output_rejects_nested_names(self, tmp_path, name):
        with pytest.raises(ValueError):
            LocalWorkspace(tmp_path).write_output("run1", name, b"", "text/plain")

    def test_exists(self, tmp_path):
        (tmp_path / "f").write_text("")
        ws = LocalWorkspace(tmp_path)
        assert ws.exists("f")
        assert not ws.exists("g")
        assert not ws.exists("../f")


class TestEnvSecretProvider:
    def test_reads_env(self, monkeypatch):
        monkeypatch.setenv("AC_TEST_PASS", "pw")
        assert EnvSecretProvider().get("AC_TEST_PASS") == "pw"

    def test_missing_raises(self, monkeypatch):
        monkeypatch.delenv("AC_NOPE", raising=False)
        with pytest.raises(SecretNotFound):
            EnvSecretProvider().get("AC_NOPE")


class TestInMemoryResultStore:
    def test_save_and_previous(self):
        from datetime import UTC, datetime

        store = InMemoryResultStore()
        r1 = RunResult(id="r1", started_at=datetime(2026, 10, 1, tzinfo=UTC), tool_version="0")
        r2 = RunResult(id="r2", started_at=datetime(2026, 10, 2, tzinfo=UTC), tool_version="0")
        store.save_run(r1)
        store.save_run(r2)
        assert store.get_run("r2") == r2
        assert store.previous_run(before="r2") == r1
        assert store.previous_run(before="r1") is None
        assert store.account_snapshot("r1", "gws") == []


def test_null_notifier_does_nothing():
    assert NullNotifier().notify({"score": 1}) is None


class TestFactory:
    def test_local(self, tmp_path):
        infra = build_infra("local", tmp_path)
        assert isinstance(infra.workspace, LocalWorkspace)
        assert isinstance(infra.secrets, EnvSecretProvider)

    def test_aws_is_not_available_yet(self, tmp_path):
        with pytest.raises(ConfigError, match="aws"):
            build_infra("aws", tmp_path)

    def test_unknown_runtime(self, tmp_path):
        with pytest.raises(ConfigError, match="unknown"):
            build_infra("gcp", tmp_path)


class TestWorkspaceHardening:
    @pytest.mark.parametrize("run_id", ["../x", "/tmp/abs", "a/../../b", "", "a/b"])
    def test_write_output_rejects_unsafe_run_id(self, tmp_path, run_id):
        with pytest.raises(ValueError):
            LocalWorkspace(tmp_path).write_output(run_id, "r.json", b"", "application/json")

    def test_glob_can_include_directories(self, tmp_path):
        (tmp_path / "inputs" / "repos" / "a").mkdir(parents=True)
        (tmp_path / "inputs" / "repos" / "f.txt").write_text("")
        ws = LocalWorkspace(tmp_path)
        assert ws.glob_inputs("inputs/repos/*") == ["inputs/repos/f.txt"]
        assert ws.glob_inputs("inputs/repos/*", include_dirs=True) == [
            "inputs/repos/a",
            "inputs/repos/f.txt",
        ]
