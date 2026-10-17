"""Per-run context handed to every check."""

from __future__ import annotations

import json
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
    # sortable timestamp prefix + 64 random bits so concurrent runs never collide
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:16]


@dataclass
class Context:
    scope: ScopeConfig
    infra: Infra
    options: RunOptions
    guard: ScopeGuard
    run_id: str
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    # hosts whose certificate failed verification; later requests skip the verified attempt
    untrusted_tls_hosts: set[str] = field(default_factory=set)
    _http: GuardedHttpClient | None = None
    _http_unverified: GuardedHttpClient | None = None

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
        """Scope-guarded HTTP client with certificate verification, created on first use."""
        if self._http is None:
            self._http = self._new_client(verify=True)
        return self._http

    @property
    def http_unverified(self) -> GuardedHttpClient:
        """Client that skips certificate verification, for inspecting broken TLS only.

        It refuses to send credentials; use ``http`` for anything else.
        """
        if self._http_unverified is None:
            self._http_unverified = self._new_client(verify=False)
        return self._http_unverified

    def _new_client(self, *, verify: bool) -> GuardedHttpClient:
        limits = self.scope.limits
        return GuardedHttpClient(
            self.guard,
            request_log=self.request_log,
            rps=limits.rps_per_host,
            concurrency=limits.concurrency,
            timeout=limits.timeout_sec,
            verify=verify,
        )

    def audit(self, entry: dict[str, Any]) -> None:
        """Record network activity that does not go through GuardedHttpClient (e.g. sslyze)."""
        path = self.request_log
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        line = {"ts": datetime.now(UTC).isoformat(), **entry}
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")

    async def aclose(self) -> None:
        for client in (self._http, self._http_unverified):
            if client is not None:
                await client.aclose()
        self._http = self._http_unverified = None
