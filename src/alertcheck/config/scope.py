"""`scope.yaml` models (spec §6.1, design §5.1)."""

from __future__ import annotations

import ipaddress
import re
from datetime import date
from pathlib import Path
from typing import Any, Self
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


class ConfigError(Exception):
    """Raised when a configuration file cannot be loaded; the message is user-facing."""


_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Authorization(_Strict):
    confirmed: bool = False
    approver: str | None = None
    confirmed_at: date | None = None
    note: str = ""

    @model_validator(mode="after")
    def _require_who_and_when(self) -> Self:
        if self.confirmed:
            if not self.approver:
                raise ValueError("approver is required when confirmed is true")
            if self.confirmed_at is None:
                raise ValueError("confirmed_at is required when confirmed is true")
        return self


class Targets(_Strict):
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def _check_domains(cls, values: list[str]) -> list[str]:
        out = []
        for value in values:
            domain = value.strip().lower().rstrip(".")
            labels = domain.split(".")
            if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
                raise ValueError(f"invalid domain: {value!r}")
            out.append(domain)
        return out

    @field_validator("urls")
    @classmethod
    def _check_urls(cls, values: list[str]) -> list[str]:
        for value in values:
            parts = urlsplit(value)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"URL must be http(s) with a host: {value!r}")
        return values

    @field_validator("hosts")
    @classmethod
    def _check_hosts(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                ipaddress.ip_address(value)
            except ValueError as e:
                raise ValueError(f"invalid IP address: {value!r}") from e
        return values

    @field_validator("cidrs")
    @classmethod
    def _check_cidrs(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as e:
                raise ValueError(f"invalid CIDR: {value!r}") from e
        return values


class Limits(_Strict):
    rps_per_host: float = Field(default=5, gt=0, le=100)
    concurrency: int = Field(default=4, ge=1, le=64)
    timeout_sec: float = Field(default=10, gt=0, le=120)
    allow_private_targets: bool = False


class TestAccount(_Strict):
    username_env: str = "AC_TEST_USER"
    password_env: str = "AC_TEST_PASS"


class Active(_Strict):
    enabled: bool = False
    test_account: TestAccount = Field(default_factory=TestAccount)


class LogInput(_Strict):
    path: str
    format: str
    site: str = ""


class AccountInput(_Strict):
    path: str
    service: str
    mapping: str
    columns: dict[str, str] = Field(default_factory=dict)


class DepInput(_Strict):
    path: str | None = None
    image: str | None = None

    @model_validator(mode="after")
    def _one_of(self) -> Self:
        if not self.path and not self.image:
            raise ValueError("each deps entry needs path or image")
        return self


class Inputs(_Strict):
    access_logs: list[LogInput] = Field(default_factory=list)
    auth_logs: list[LogInput] = Field(default_factory=list)
    accounts: list[AccountInput] = Field(default_factory=list)
    roster: str | None = None
    deps: list[DepInput] = Field(default_factory=list)
    data_inventory: str | None = None


class AwsCloud(_Strict):
    enabled: bool = False
    regions: list[str] = Field(default_factory=lambda: ["ap-northeast-1"])


class Cloud(_Strict):
    aws: AwsCloud = Field(default_factory=AwsCloud)


class ScopeConfig(_Strict):
    organization: str
    authorization: Authorization = Field(default_factory=Authorization)
    targets: Targets = Field(default_factory=Targets)
    exclude: list[str] = Field(default_factory=list)
    asset_inventory: str | None = None
    url_allowlist: str | None = None
    api_endpoints: str | None = None
    limits: Limits = Field(default_factory=Limits)
    active: Active = Field(default_factory=Active)
    inputs: Inputs = Field(default_factory=Inputs)
    cloud: Cloud = Field(default_factory=Cloud)


def _format_errors(err: ValidationError) -> str:
    lines = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "(root)"
        msg = e["msg"].removeprefix("Value error, ")
        lines.append(f"  - {loc}: {msg}")
    return "\n".join(lines)


def read_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"{path}: file not found")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"{path}: invalid YAML: {e}") from e
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def load_scope(path: Path) -> ScopeConfig:
    data = read_yaml_mapping(path)
    try:
        return ScopeConfig.model_validate(data)
    except ValidationError as e:
        raise ConfigError(f"{path}: invalid scope\n{_format_errors(e)}") from e
