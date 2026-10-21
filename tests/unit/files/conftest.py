import datetime as dt
import shutil
from pathlib import Path

import pytest

from alertcheck.config.scope import ScopeConfig
from alertcheck.core.context import Context, RunOptions
from alertcheck.infra.factory import build_infra

FIX = Path(__file__).parents[2] / "fixtures"
TODAY = dt.date(2026, 10, 21)


@pytest.fixture
def make_ctx(tmp_path):
    def factory(inputs=None, copy=None, run_id="run-now", **scope_kw):
        ws = tmp_path / "ws"
        (ws / "inputs").mkdir(parents=True, exist_ok=True)
        for src, dst in (copy or {}).items():
            target = ws / dst
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(FIX / src, target)
        data = {"organization": "X", "inputs": inputs or {}}
        data.update(scope_kw)
        scope = ScopeConfig.model_validate(data)
        return Context.create(
            scope=scope, infra=build_infra("local", ws), options=RunOptions(), run_id=run_id
        )

    return factory
