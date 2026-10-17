"""Runs registered checks stage by stage (design §2, §7.1)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from alertcheck import __version__
from alertcheck.core.context import Context
from alertcheck.core.masking import mask_evidence
from alertcheck.core.models import CheckResult, Coverage, Finding, RunResult
from alertcheck.core.registry import Check, Registry


def _matches(check: Check, selectors: frozenset[str]) -> bool:
    return any(check.id == s or check.id.startswith(s + ".") or check.group == s for s in selectors)


def _will_run(coverage: list[Coverage]) -> bool:
    return any(c.status == "executed" for c in coverage)


class Orchestrator:
    def __init__(self, registry: Registry, ctx: Context) -> None:
        self._registry = registry
        self._ctx = ctx

    def _gate(self, check: Check) -> str | None:
        """Reason the check must not run because of options or authorization."""
        opts = self._ctx.options
        if opts.only and not _matches(check, opts.only):
            return "not selected by --only"
        if opts.skip and _matches(check, opts.skip):
            return "excluded by --skip"
        if check.group == "network" and not self._ctx.guard.authorized:
            return "authorization.confirmed is false"
        if check.group in ("network", "cloud") and opts.offline:
            return "--offline"
        if check.active and not opts.active:
            return "active check; requires --active"
        return None

    def _skipped(self, check: Check, reason: str) -> list[Coverage]:
        return [Coverage(check_id=check.id, target="*", status="skipped_by_option", detail=reason)]

    def _error(self, check: Check, e: Exception) -> list[Coverage]:
        detail = f"{type(e).__name__}: {e}"
        return [Coverage(check_id=check.id, target="*", status="error", detail=detail)]

    def _plan_check(self, check: Check) -> list[Coverage]:
        reason = self._gate(check)
        if reason is not None:
            return self._skipped(check, reason)
        try:
            return check.plan(self._ctx)
        except Exception as e:  # a broken plan must not abort the whole run
            return self._error(check, e)

    def plan(self) -> list[Coverage]:
        """Pre-flight view; mirrors run() including dependency readiness."""
        coverage: list[Coverage] = []
        ready: set[str] = set()
        for stage in self._registry.stages():
            for check in stage:
                missing = [d for d in check.requires if d not in ready]
                if missing:
                    coverage += self._skipped(check, f"dependency {missing[0]} will not run")
                    continue
                planned = self._plan_check(check)
                if _will_run(planned):
                    ready.add(check.id)
                coverage += planned
        return coverage

    async def _run_one(self, check: Check) -> CheckResult:
        try:
            result = await check.run(self._ctx)
        except Exception as e:  # one broken check must not abort the whole run
            return CheckResult(coverage=self._error(check, e))
        result.findings = [
            Finding.model_validate({**f.model_dump(), "evidence": mask_evidence(f.evidence)})
            for f in result.findings
        ]
        return result

    async def run(self) -> RunResult:
        started = datetime.now(UTC)
        findings: list[Finding] = []
        coverage: list[Coverage] = []
        executed: set[str] = set()
        try:
            for stage in self._registry.stages():
                runnable: list[Check] = []
                for check in stage:
                    missing = [d for d in check.requires if d not in executed]
                    if missing:
                        coverage += self._skipped(check, f"dependency {missing[0]} did not run")
                        continue
                    planned = self._plan_check(check)
                    if _will_run(planned):
                        runnable.append(check)
                    else:
                        coverage += planned
                async with asyncio.TaskGroup() as tg:
                    tasks = [tg.create_task(self._run_one(c)) for c in runnable]
                for check, task in zip(runnable, tasks, strict=True):
                    result = task.result()
                    findings += result.findings
                    coverage += result.coverage
                    if result.artifacts:
                        self._ctx.artifacts[check.id] = result.artifacts
                    # only a check that actually ran can satisfy its dependents
                    if _will_run(result.coverage):
                        executed.add(check.id)
        finally:
            await self._ctx.aclose()
        opts = self._ctx.options
        return RunResult(
            id=self._ctx.run_id,
            started_at=started,
            finished_at=datetime.now(UTC),
            tool_version=__version__,
            options={
                "active": opts.active,
                "offline": opts.offline,
                "only": sorted(opts.only),
                "skip": sorted(opts.skip),
            },
            findings=findings,
            coverage=coverage,
        )
