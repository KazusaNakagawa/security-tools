"""Runs external scanners without a shell and with a timeout."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
from collections.abc import Awaitable, Callable, Sequence


class ToolNotFound(Exception):
    """The scanner binary is not installed (on PATH)."""


class ToolFailed(Exception):
    """The scanner ran but failed, timed out or produced unusable output."""


Runner = Callable[..., Awaitable[str]]


async def run_tool(argv: Sequence[str], *, timeout: float, ok_codes: Sequence[int] = (0,)) -> str:
    """Run ``argv`` (argument list, never a shell string) and return stdout."""
    executable = shutil.which(argv[0])
    if executable is None:
        raise ToolNotFound(f"{argv[0]} not installed")
    proc = await asyncio.create_subprocess_exec(
        executable,
        *argv[1:],
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,  # own process group, so a timeout also stops its children
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        await proc.wait()
        raise ToolFailed(f"{argv[0]} timed out after {timeout:.0f}s") from None
    if proc.returncode not in ok_codes:
        tail = stderr.decode(errors="replace").strip()[-500:]
        raise ToolFailed(f"{argv[0]} exited {proc.returncode}: {tail}")
    return stdout.decode(errors="replace")
