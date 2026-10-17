import os
import stat

import pytest

from alertcheck.adapters.process import ToolFailed, ToolNotFound, run_tool


def fake_tool(tmp_path, name, script):
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.fixture
def path_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}/usr/bin:/bin")
    return tmp_path


async def test_stdout_is_returned(path_env):
    fake_tool(path_env, "faketool", 'echo "{\\"ok\\": $1}"\n')
    assert (await run_tool(["faketool", "1"], timeout=5)).strip() == '{"ok": 1}'


async def test_arguments_are_not_shell_interpreted(path_env):
    fake_tool(path_env, "faketool", 'printf "%s" "$1"\n')
    assert (
        await run_tool(["faketool", "$(echo pwned); rm -rf /"], timeout=5)
        == "$(echo pwned); rm -rf /"
    )


async def test_missing_tool(path_env):
    with pytest.raises(ToolNotFound):
        await run_tool(["definitely-not-installed-tool"], timeout=5)


async def test_allowed_nonzero_exit(path_env):
    fake_tool(path_env, "faketool", "echo found; exit 1\n")
    assert (await run_tool(["faketool"], timeout=5, ok_codes=(0, 1))).strip() == "found"


async def test_failing_exit_includes_stderr(path_env):
    fake_tool(path_env, "faketool", "echo boom >&2; exit 2\n")
    with pytest.raises(ToolFailed, match="exited 2: boom"):
        await run_tool(["faketool"], timeout=5)


async def test_timeout_kills_process(path_env):
    fake_tool(path_env, "faketool", "sleep 5\n")
    with pytest.raises(ToolFailed, match="timed out"):
        await run_tool(["faketool"], timeout=0.3)
