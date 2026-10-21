"""Account ledger CSVs mapped to a common schema (design §5.2, §7.4)."""

from __future__ import annotations

import csv
import datetime as dt
import io
import re
from dataclasses import dataclass

_TRUE = {"true", "yes", "1", "enabled", "on", "active"}
_ADMIN = re.compile(r"admin|owner|superuser|root", re.IGNORECASE)
_DISABLED = {"suspended", "disabled", "inactive", "deprovisioned", "archived"}
_DELETED = {"deleted", "removed"}


@dataclass
class AccountRow:
    account_id: str
    status: str  # active | disabled | deleted
    role: str
    email: str | None = None
    display_name: str | None = None
    mfa: bool | None = None
    created_at: dt.date | None = None
    last_login_at: dt.date | None = None
    owner: str | None = None

    @property
    def is_admin(self) -> bool:
        return bool(_ADMIN.search(self.role))

    def days_since_login(self, *, today: dt.date) -> int | None:
        if self.last_login_at is None:
            return None
        return (today - self.last_login_at).days


@dataclass
class RosterEntry:
    email: str
    retired: bool


def _norm_email(value: str | None) -> str | None:
    value = (value or "").strip().lower()
    return value or None


def _parse_date(value: str | None) -> dt.date | None:
    value = (value or "").strip()
    if not value or value.lower() in ("never", "never logged in", "-", "none"):
        return None
    text = value.replace("/", "-").split(" ")[0].split("T")[0]
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        return None


def _parse_bool(value: str | None) -> bool | None:
    value = (value or "").strip().lower()
    if not value:
        return None
    return value in _TRUE


def _norm_status(value: str | None) -> str:
    value = (value or "").strip().lower()
    if value in _DELETED:
        return "deleted"
    if value in _DISABLED:
        return "disabled"
    return "active"


def _row_from(record: dict[str, str], cols: dict[str, str]) -> AccountRow:
    def get(field: str) -> str | None:
        column = cols.get(field)
        return record.get(column) if column else None

    email = _norm_email(get("email"))
    account_id = (get("id") or email or "").strip()
    return AccountRow(
        account_id=account_id,
        status=_norm_status(get("status")),
        role=(get("role") or "").strip() or "user",
        email=email,
        display_name=(get("display_name") or "").strip() or None,
        mfa=_parse_bool(get("mfa")),
        created_at=_parse_date(get("created_at")),
        last_login_at=_parse_date(get("last_login_at")),
        owner=(get("owner") or "").strip() or None,
    )


# built-in column mappings per service export format
_MAPPINGS: dict[str, dict[str, str]] = {
    "gws": {
        "id": "Email Address [Required]",
        "email": "Email Address [Required]",
        "status": "Status [READ ONLY]",
        "role": "Admin Role",
        "mfa": "2sv Enrolled [READ ONLY]",
        "last_login_at": "Last Sign In [READ ONLY]",
    },
    "entra": {
        "id": "userPrincipalName",
        "email": "userPrincipalName",
        "display_name": "displayName",
        "status": "accountEnabled",
        "role": "directoryRoles",
    },
    "github": {
        "id": "login",
        "email": "email",
        "role": "role",
        "status": "state",
        "mfa": "mfa_enabled",
        "last_login_at": "last_active",
    },
    "aws_iam": {
        "id": "user",
        "status": "password_enabled",
        "mfa": "mfa_active",
        "created_at": "user_creation_time",
        "last_login_at": "password_last_used",
    },
}
_REQUIRED = ("id", "status", "role")


def load_accounts(text: str, *, mapping: str, columns: dict[str, str]) -> list[AccountRow]:
    if mapping == "custom":
        cols = columns
    elif mapping in _MAPPINGS:
        cols = {**_MAPPINGS[mapping], **columns}
    else:
        raise ValueError(f"unknown mapping: {mapping!r} (use one of {sorted(_MAPPINGS)} or custom)")
    missing = [f for f in _REQUIRED if f not in cols]
    if missing:
        raise ValueError(f"mapping is missing required field(s): {', '.join(missing)}")

    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for record in reader:
        row = _row_from(record, cols)
        if row.account_id:
            # GWS marks admins in a free-text role column; normalize to "admin"
            if mapping == "gws" and row.role and row.role != "user":
                row.role = "admin"
            rows.append(row)
    return rows


def load_roster(text: str) -> dict[str, RosterEntry]:
    reader = csv.DictReader(io.StringIO(text))
    roster: dict[str, RosterEntry] = {}
    for record in reader:
        email = _norm_email(record.get("email"))
        if not email:
            continue
        status = (record.get("status") or "").strip().lower()
        roster[email] = RosterEntry(
            email=email, retired=status in ("retired", "resigned", "terminated")
        )
    return roster
