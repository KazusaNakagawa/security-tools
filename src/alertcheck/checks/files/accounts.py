"""accounts: audit account ledgers against a roster and the previous run (design §7.4).

IPA P2-3 (abnormal accounts), A-3 (privileges), S-1..S-3 (external services).
Re-enable detection compares each service against the latest stored snapshot
and writes the current one for the next run.
"""

from __future__ import annotations

import collections
import datetime as dt
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import ClassVar, Literal

import yaml
from pydantic import BaseModel, ConfigDict

from alertcheck.checks.files.account_schema import (
    AccountRow,
    RosterEntry,
    load_accounts,
    load_roster,
)
from alertcheck.config.scope import AccountInput
from alertcheck.core.context import Context
from alertcheck.core.models import CheckResult, Coverage, Finding, Severity

_INACTIVE_DAYS = 90
_RECENT_ADMIN_DAYS = 90
_ADMIN_RATIO = 0.10
_SHARED_NAMES = {
    "admin",
    "administrator",
    "test",
    "shared",
    "info",
    "root",
    "service",
    "guest",
    "demo",
}


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    ipa_items: list[str]
    severity: dict[str, str] | str
    description: str
    remediation: str

    def level(self, is_admin: bool) -> Severity:
        if isinstance(self.severity, str):
            return Severity(self.severity)
        return Severity(self.severity["admin"] if is_admin else self.severity["other"])


@cache
def load_rules() -> list[Rule]:
    raw = files("alertcheck.data").joinpath("account_rules.yaml").read_text(encoding="utf-8")
    return [Rule.model_validate(r) for r in yaml.safe_load(raw)["rules"]]


@dataclass
class _Ledger:
    service: str
    rows: list[AccountRow]


class AccountsCheck:
    id: ClassVar[str] = "accounts"
    group: ClassVar[Literal["files"]] = "files"
    ipa_items: ClassVar[list[str]] = ["P2-3", "A-3", "S-1", "S-2", "S-3"]
    requires: ClassVar[list[str]] = []
    active: ClassVar[bool] = False

    def __init__(self, today: dt.date | None = None) -> None:
        self._today = today or dt.date.today()
        self._rules = {r.id: r for r in load_rules()}

    def plan(self, ctx: Context) -> list[Coverage]:
        entries = ctx.scope.inputs.accounts
        if not entries:
            return [
                Coverage(
                    check_id=self.id,
                    target="*",
                    status="skipped_no_input",
                    detail="no accounts input",
                )
            ]
        return [Coverage(check_id=self.id, target=e.service, status="executed") for e in entries]

    async def run(self, ctx: Context) -> CheckResult:
        result = CheckResult()
        roster = self._load_roster(ctx, result)
        for entry in ctx.scope.inputs.accounts:
            self._audit_service(ctx, entry, roster, result)
        return result

    def _load_roster(self, ctx: Context, result: CheckResult) -> dict[str, RosterEntry]:
        if not ctx.scope.inputs.roster:
            return {}
        try:
            with ctx.infra.workspace.open_input(ctx.scope.inputs.roster) as f:
                return load_roster(f.read().decode("utf-8-sig"))
        except (OSError, PermissionError, UnicodeDecodeError) as e:
            result.coverage.append(
                Coverage(
                    check_id=self.id,
                    target="roster",
                    status="error",
                    detail=f"roster unreadable: {e}",
                )
            )
            return {}

    def _audit_service(
        self, ctx: Context, entry: AccountInput, roster: dict[str, RosterEntry], result: CheckResult
    ) -> None:
        try:
            with ctx.infra.workspace.open_input(entry.path) as f:
                rows = load_accounts(
                    f.read().decode("utf-8-sig"), mapping=entry.mapping, columns=entry.columns
                )
        except (OSError, PermissionError, UnicodeDecodeError, ValueError) as e:
            result.coverage.append(
                Coverage(
                    check_id=self.id, target=entry.service, status="error", detail=str(e)[:300]
                )
            )
            return

        previous = ctx.infra.store.latest_account_snapshot(entry.service, exclude=ctx.run_id)
        prev_status = {r["account_id"]: r["status"] for r in previous}
        notes = [] if previous else ["前回データなし（再有効化は次回以降に判定）"]

        result.findings += self._evaluate(entry.service, rows, roster, prev_status)
        self._save_snapshot(ctx, entry.service, rows)
        result.coverage.append(
            Coverage(
                check_id=self.id,
                target=entry.service,
                status="executed",
                detail=f"{len(rows)} accounts; " + ("; ".join(notes) if notes else ""),
            )
        )

    def _save_snapshot(self, ctx: Context, service: str, rows: list[AccountRow]) -> None:
        ctx.infra.store.save_account_snapshot(
            ctx.run_id,
            service,
            [
                {"account_id": r.account_id, "status": r.status, "role": r.role, "mfa": r.mfa}
                for r in rows
            ],
        )

    def _evaluate(
        self,
        service: str,
        rows: list[AccountRow],
        roster: dict[str, RosterEntry],
        prev_status: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        active = [r for r in rows if r.status == "active"]
        admins = [r for r in active if r.is_admin]
        email_counts = collections.Counter(r.email for r in rows if r.email)

        for row in rows:
            findings += self._row_findings(service, row, roster, prev_status, email_counts)

        if active and (len(admins) / len(active) > _ADMIN_RATIO and len(admins) > 1):
            findings.append(
                self._finding(
                    service,
                    self._rules["admin_excess"],
                    None,
                    detail=f"管理者 {len(admins)} / 有効 {len(active)}",
                    evidence={"admins": len(admins), "active": len(active)},
                )
            )
        return findings

    def _row_findings(
        self,
        service: str,
        row: AccountRow,
        roster: dict[str, RosterEntry],
        prev_status: dict[str, str],
        email_counts: collections.Counter,
    ) -> list[Finding]:
        out: list[Finding] = []

        def add(rule_id: str, **evidence: object) -> None:
            out.append(self._finding(service, self._rules[rule_id], row, evidence=evidence))

        if row.status == "active":
            entry = roster.get(row.email) if row.email else None
            if entry and entry.retired:
                add("retired_employee")
            elif not entry and not row.owner and roster:
                add("unknown_account")
            if prev_status.get(row.account_id) in ("disabled", "deleted"):
                add("reenabled", previous=prev_status[row.account_id])
            if row.mfa is False:
                add("mfa_off")
            if (
                row.is_admin
                and row.created_at
                and (self._today - row.created_at).days <= _RECENT_ADMIN_DAYS
            ):
                add("recent_admin", created_at=row.created_at.isoformat())
            days = row.days_since_login(today=self._today)
            if days is not None and days >= _INACTIVE_DAYS:
                add("inactive", days_since_login=days)

        if self._is_shared(row, email_counts):
            add("shared_account")
        if row.created_at and row.last_login_at and row.last_login_at < row.created_at:
            add(
                "login_before_creation",
                created_at=row.created_at.isoformat(),
                last_login_at=row.last_login_at.isoformat(),
            )
        return out

    def _is_shared(self, row: AccountRow, email_counts: collections.Counter) -> bool:
        name = row.account_id.lower().split("@")[0]
        if name in _SHARED_NAMES:
            return True
        return bool(row.email and email_counts[row.email] > 1)

    def _finding(
        self,
        service: str,
        rule: Rule,
        row: AccountRow | None,
        *,
        detail: str = "",
        evidence: dict | None = None,
    ) -> Finding:
        account = row.account_id if row else service
        is_admin = row.is_admin if row else True
        ev = {"rule": rule.id, "service": service, **(evidence or {})}
        if row is not None:
            ev["account"] = row.account_id
        return Finding.create(
            check_id=self.id,
            kind=f"{rule.id}:{service}:{account}",
            target=f"{service}/{account}",
            ipa_items=rule.ipa_items,
            severity=rule.level(is_admin),
            title=f"{rule.title}（{account}）" if row else rule.title,
            description=rule.description + (f" {detail}" if detail else ""),
            remediation=rule.remediation,
            evidence=ev,
        )
