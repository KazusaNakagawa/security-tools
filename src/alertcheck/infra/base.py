"""Interfaces that differ between the local and AWS runtimes (design §14.2)."""

from __future__ import annotations

from typing import Any, BinaryIO, Protocol

from alertcheck.core.models import RunResult


class SecretNotFound(KeyError):
    """The requested secret is not available from the provider."""


class Workspace(Protocol):
    """Reads input files and writes run outputs."""

    def open_input(self, path: str) -> BinaryIO: ...
    def glob_inputs(self, pattern: str, *, include_dirs: bool = False) -> list[str]: ...
    def exists(self, path: str) -> bool: ...
    def write_output(self, run_id: str, name: str, data: bytes, content_type: str) -> str: ...


class ResultStore(Protocol):
    """Stores runs, findings, verdicts and account snapshots."""

    def save_run(self, run: RunResult) -> None: ...
    def get_run(self, run_id: str) -> RunResult | None: ...
    def previous_run(self, before: str) -> RunResult | None: ...
    def account_snapshot(self, run_id: str, service: str) -> list[dict[str, Any]]: ...


class SecretProvider(Protocol):
    """Returns credentials such as the test account password or DB DSN."""

    def get(self, name: str) -> str: ...


class Notifier(Protocol):
    """Sends a run summary somewhere (no-op locally)."""

    def notify(self, summary: dict[str, Any]) -> None: ...
