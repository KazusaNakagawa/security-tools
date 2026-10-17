"""Check plugin interface and registry (design §7.1)."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from alertcheck.core.context import Context
    from alertcheck.core.models import CheckResult, Coverage

ENTRY_POINT_GROUP = "alertcheck.checks"


class Check(Protocol):
    id: str
    group: Literal["network", "files", "cloud"]
    ipa_items: list[str]
    requires: list[str]
    active: bool

    def plan(self, ctx: Context) -> list[Coverage]:
        """Return coverage with status ``executed`` for targets it will run on."""
        ...

    async def run(self, ctx: Context) -> CheckResult: ...


class RegistryError(Exception):
    pass


class Registry:
    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, check: Check) -> None:
        if check.id in self._checks:
            raise RegistryError(f"duplicate check id: {check.id}")
        self._checks[check.id] = check

    def all(self) -> list[Check]:
        return list(self._checks.values())

    @classmethod
    def from_entry_points(cls, group: str = ENTRY_POINT_GROUP) -> Registry:
        registry = cls()
        for ep in entry_points(group=group):
            try:
                factory = ep.load()
                registry.register(factory())
            except RegistryError:
                raise
            except Exception as e:
                raise RegistryError(f"failed to load check plugin {ep.name!r}: {e}") from e
        return registry

    def stages(self) -> list[list[Check]]:
        """Group checks into stages; every check runs after all of its requirements."""
        for check in self._checks.values():
            for dep in check.requires:
                if dep not in self._checks:
                    raise RegistryError(f"check {check.id!r} requires unknown check {dep!r}")
        remaining = dict(self._checks)
        done: set[str] = set()
        stages: list[list[Check]] = []
        while remaining:
            ready = [c for c in remaining.values() if set(c.requires) <= done]
            if not ready:
                raise RegistryError(f"dependency cycle among: {', '.join(sorted(remaining))}")
            ready.sort(key=lambda c: c.id)
            stages.append(ready)
            for c in ready:
                done.add(c.id)
                del remaining[c.id]
        return stages
