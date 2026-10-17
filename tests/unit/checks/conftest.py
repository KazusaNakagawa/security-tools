import pytest

from alertcheck.config.scope import ScopeConfig
from alertcheck.core.context import Context, RunOptions
from alertcheck.core.scope_guard import ScopeGuard
from alertcheck.infra.factory import build_infra

AUTH = {"confirmed": True, "approver": "a", "confirmed_at": "2026-10-17"}


def static_resolver(table=None, default="93.184.216.34"):
    table = table or {}

    async def resolve(host):
        return table.get(host, [default])

    return resolve


@pytest.fixture
def make_ctx(tmp_path):
    contexts = []

    def factory(targets=None, resolver=None, **scope_kw):
        data = {
            "organization": "X",
            "authorization": AUTH,
            "targets": {"urls": ["https://www.example.co.jp/"]} if targets is None else targets,
            "limits": {"rps_per_host": 100},
        }
        data.update(scope_kw)
        scope = ScopeConfig.model_validate(data)
        guard = ScopeGuard(scope, resolver=resolver or static_resolver())
        ctx = Context.create(
            scope=scope, infra=build_infra("local", tmp_path), options=RunOptions(), guard=guard
        )
        contexts.append(ctx)
        return ctx

    yield factory


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch):
    """Checks issue hundreds of requests; pacing is covered by test_ratelimit.py."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def slot(self, host):
        yield

    monkeypatch.setattr("alertcheck.core.ratelimit.HostRateLimiter.slot", slot)
