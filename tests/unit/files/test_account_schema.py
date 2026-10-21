import datetime as dt
from pathlib import Path

import pytest

from alertcheck.checks.files.account_schema import AccountRow, load_accounts, load_roster

FIX = Path(__file__).parents[2] / "fixtures" / "accounts"


class TestMappings:
    def test_custom_mapping(self):
        rows = load_accounts(
            (FIX / "custom.csv").read_text(),
            mapping="custom",
            columns={
                "id": "login",
                "email": "mail",
                "role": "role",
                "status": "status",
                "mfa": "mfa",
                "created_at": "created_at",
                "last_login_at": "last_login_at",
            },
        )
        admin = next(r for r in rows if r.account_id == "admin")
        assert admin.role == "admin" and admin.is_admin
        assert admin.status == "active" and admin.mfa is False
        assert admin.created_at == dt.date(2026, 10, 1)
        assert next(r for r in rows if r.account_id == "alice").mfa is True

    def test_google_workspace_mapping(self):
        rows = load_accounts((FIX / "gws.csv").read_text(), mapping="gws", columns={})
        by_email = {r.email: r for r in rows}
        yamada = by_email["yamada@example.co.jp"]
        assert yamada.is_admin and yamada.mfa is True and yamada.status == "active"
        assert by_email["tanaka@example.co.jp"].status == "disabled"
        assert by_email["suzuki@example.co.jp"].last_login_at == dt.date(2026, 7, 1)
        assert by_email["sato@example.co.jp"].last_login_at is None  # never logged in

    def test_unknown_mapping(self):
        with pytest.raises(ValueError, match="unknown mapping"):
            load_accounts("a,b\n1,2\n", mapping="nope", columns={})

    def test_missing_required_column(self):
        with pytest.raises(ValueError, match="status"):
            load_accounts(
                "login,role\nx,user\n", mapping="custom", columns={"id": "login", "role": "role"}
            )


class TestRoster:
    def test_load(self):
        roster = load_roster((FIX / "roster.csv").read_text())
        assert roster["carol@example.co.jp"].retired
        assert not roster["yamada@example.co.jp"].retired

    def test_email_is_normalized(self):
        roster = load_roster("email,status\n  Yamada@Example.CO.JP , active\n")
        assert "yamada@example.co.jp" in roster


class TestAccountRow:
    def test_days_since_login(self):
        row = AccountRow(
            account_id="x", status="active", role="user", last_login_at=dt.date(2026, 1, 1)
        )
        assert row.days_since_login(today=dt.date(2026, 10, 21)) == 293

    def test_days_since_login_never(self):
        assert (
            AccountRow(account_id="x", status="active", role="user").days_since_login(
                today=dt.date(2026, 10, 21)
            )
            is None
        )


class TestBooleanStatus:
    def test_entra_disabled_account(self):
        rows = load_accounts(
            "userPrincipalName,accountEnabled,directoryRoles\n"
            "a@example.co.jp,false,User\nb@example.co.jp,true,Global Administrator\n",
            mapping="entra",
            columns={},
        )
        by = {r.account_id: r for r in rows}
        assert by["a@example.co.jp"].status == "disabled"
        assert by["b@example.co.jp"].status == "active"

    def test_iam_password_disabled(self):
        rows = load_accounts(
            "user,password_enabled,mfa_active,user_creation_time,password_last_used\n"
            "svc,false,false,2024-01-01,2024-02-01\n",
            mapping="aws_iam",
            columns={},
        )
        assert rows[0].status == "disabled"
