from alertcheck.config.scope import ScopeConfig
from alertcheck.core.context import Context, new_run_id
from alertcheck.infra.factory import build_infra


def test_run_ids_are_unique_and_sortable():
    ids = [new_run_id() for _ in range(1000)]
    assert len(set(ids)) == 1000
    assert all(len(i.split("-")[-1]) >= 12 for i in ids)


async def test_unverified_client_is_separate(tmp_path):
    scope = ScopeConfig(organization="X")
    c = Context.create(scope=scope, infra=build_infra("local", tmp_path))
    assert c.http.verify is True
    assert c.http_unverified.verify is False
    assert c.http is not c.http_unverified
    await c.aclose()
