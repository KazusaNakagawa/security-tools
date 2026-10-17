"""Local runtime implementations: files under the workspace, env vars, no notifications."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, BinaryIO

from alertcheck.core.models import RunResult
from alertcheck.infra.base import SecretNotFound

# one path component: no separators, not "." or "..", no leading dot
_SAFE_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")


class LocalWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _resolve(self, path: str) -> Path:
        base = self.root.resolve()
        candidate = (base / path).resolve()
        if not candidate.is_relative_to(base):
            raise PermissionError(f"path escapes the workspace: {path}")
        return candidate

    def open_input(self, path: str) -> BinaryIO:
        return self._resolve(path).open("rb")

    def glob_inputs(self, pattern: str, *, include_dirs: bool = False) -> list[str]:
        self._resolve(pattern)  # reject patterns that point outside the workspace
        base = self.root.resolve()
        matches = []
        for match in base.glob(pattern):
            resolved = match.resolve()
            wanted = resolved.is_file() or (include_dirs and resolved.is_dir())
            if wanted and resolved.is_relative_to(base):
                matches.append(match.relative_to(base).as_posix())
        return sorted(matches)

    def local_path(self, path: str) -> Path:
        return self._resolve(path)

    def exists(self, path: str) -> bool:
        try:
            return self._resolve(path).exists()
        except PermissionError:
            return False

    def run_dir(self, run_id: str) -> Path:
        if not _SAFE_NAME.fullmatch(run_id):
            raise ValueError(f"run id must be a plain identifier: {run_id!r}")
        return self.root / "out" / "runs" / run_id

    def write_output(self, run_id: str, name: str, data: bytes, content_type: str) -> str:
        if not _SAFE_NAME.fullmatch(name):
            raise ValueError(f"output name must be a plain file name: {name!r}")
        target = self.run_dir(run_id) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return str(target)


class EnvSecretProvider:
    def get(self, name: str) -> str:
        try:
            return os.environ[name]
        except KeyError:
            raise SecretNotFound(name) from None


class NullNotifier:
    def notify(self, summary: dict[str, Any]) -> None:
        return None


class InMemoryResultStore:
    """Placeholder until the SQLite store lands (issue #6)."""

    def __init__(self) -> None:
        self._runs: dict[str, RunResult] = {}

    def save_run(self, run: RunResult) -> None:
        self._runs[run.id] = run

    def get_run(self, run_id: str) -> RunResult | None:
        return self._runs.get(run_id)

    def previous_run(self, before: str) -> RunResult | None:
        current = self._runs.get(before)
        if current is None:
            return None
        earlier = [r for r in self._runs.values() if r.started_at < current.started_at]
        return max(earlier, key=lambda r: r.started_at, default=None)

    def account_snapshot(self, run_id: str, service: str) -> list[dict[str, Any]]:
        return []
