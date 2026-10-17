"""Builds the infra implementations for the selected runtime."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alertcheck.config.scope import ConfigError
from alertcheck.infra.base import Notifier, ResultStore, SecretProvider, Workspace
from alertcheck.infra.local import (
    EnvSecretProvider,
    InMemoryResultStore,
    LocalWorkspace,
    NullNotifier,
)


@dataclass
class Infra:
    workspace: Workspace
    store: ResultStore
    secrets: SecretProvider
    notifier: Notifier


def build_infra(runtime: str, workspace_root: Path) -> Infra:
    if runtime == "local":
        return Infra(
            workspace=LocalWorkspace(workspace_root),
            store=InMemoryResultStore(),
            secrets=EnvSecretProvider(),
            notifier=NullNotifier(),
        )
    if runtime == "aws":
        raise ConfigError("runtime 'aws' is not implemented yet (design §14)")
    raise ConfigError(f"unknown runtime: {runtime!r} (expected 'local' or 'aws')")
