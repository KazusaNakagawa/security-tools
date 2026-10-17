"""Per-run context handed to every check."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alertcheck.config.scope import ScopeConfig
from alertcheck.core.scope_guard import GuardedHttpClient, ScopeGuard
from alertcheck.infra.factory import Infra
from alertcheck.infra.local import LocalWorkspace


@dataclass(frozen=True)
class RunOptions:
    active: bool = False
    offline: bool = False
    only: frozenset[str] = frozenset()
    skip: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        # accept any iterable (e.g. a list from the CLI) but store immutably
        object.__setattr__(self, "only", frozenset(self.only))
        object.__setattr__(self, "skip", frozenset(self.skip))


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]


@dataclass
class Context:
    scope: ScopeConfig
    infra: Infra
    options: RunOptions
    guard: ScopeGuard
    run_id: str
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    _http: GuardedHttpClient | None = None

    @classmethod
    def create(
        cls,
        *,
        scope: ScopeConfig,
        infra: Infra,
        options: RunOptions | None = None,
        guard: ScopeGuard | None = None,
        run_id: str | None = None,
    ) -> Context:
        return cls(
            scope=scope,
            infra=infra,
            options=options or RunOptions(),
            guard=guard or ScopeGuard(scope),
            run_id=run_id or new_run_id(),
        )

    @property
    def request_log(self) -> Path | None:
        ws = self.infra.workspace
        if isinstance(ws, LocalWorkspace):
            return ws.run_dir(self.run_id) / "requests.jsonl"
        return None

    @property
    def http(self) -> GuardedHttpClient:
        """Scope-guarded HTTP client, created on first use."""
        if self._http is None:
            limits = self.scope.limits
            self._http = GuardedHttpClient(
                self.guard,
                request_log=self.request_log,
                rps=limits.rps_per_host,
                concurrency=limits.concurrency,
                timeout=limits.timeout_sec,
            )
        return self._http

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None
