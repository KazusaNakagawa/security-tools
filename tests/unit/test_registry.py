import pytest

from alertcheck.core.models import CheckResult, Coverage
from alertcheck.core.registry import Registry, RegistryError


class FakeCheck:
    def __init__(self, id, requires=(), group="network", active=False, ipa_items=("A-1",)):
        self.id = id
        self.group = group
        self.requires = list(requires)
        self.active = active
        self.ipa_items = list(ipa_items)

    def plan(self, ctx):
        return [Coverage(check_id=self.id, target="*", status="executed")]

    async def run(self, ctx):
        return CheckResult()


def ids(stages):
    return [sorted(c.id for c in stage) for stage in stages]


class TestStages:
    def test_independent_checks_share_a_stage(self):
        reg = Registry()
        for name in ["tls", "ports"]:
            reg.register(FakeCheck(name))
        assert ids(reg.stages()) == [["ports", "tls"]]

    def test_dependencies_are_ordered(self):
        reg = Registry()
        reg.register(FakeCheck("http.headers", requires=["discovery"]))
        reg.register(FakeCheck("vuln.version", requires=["ports", "http.headers"]))
        reg.register(FakeCheck("discovery"))
        reg.register(FakeCheck("ports", requires=["discovery"]))
        assert ids(reg.stages()) == [["discovery"], ["http.headers", "ports"], ["vuln.version"]]

    def test_empty_registry(self):
        assert Registry().stages() == []

    def test_unknown_dependency(self):
        reg = Registry()
        reg.register(FakeCheck("a", requires=["missing"]))
        with pytest.raises(RegistryError, match="missing"):
            reg.stages()

    def test_cycle(self):
        reg = Registry()
        reg.register(FakeCheck("a", requires=["b"]))
        reg.register(FakeCheck("b", requires=["a"]))
        with pytest.raises(RegistryError, match="cycle"):
            reg.stages()

    def test_duplicate_id(self):
        reg = Registry()
        reg.register(FakeCheck("a"))
        with pytest.raises(RegistryError, match="duplicate"):
            reg.register(FakeCheck("a"))


class TestEntryPoints:
    def test_loads_checks_from_entry_points(self, monkeypatch):
        class EP:
            name = "fake"

            def load(self):
                return lambda: FakeCheck("fake")

        monkeypatch.setattr("alertcheck.core.registry.entry_points", lambda group: [EP()])
        reg = Registry.from_entry_points()
        assert [c.id for c in reg.all()] == ["fake"]

    def test_broken_entry_point_is_reported(self, monkeypatch):
        class EP:
            name = "broken"

            def load(self):
                raise ImportError("boom")

        monkeypatch.setattr("alertcheck.core.registry.entry_points", lambda group: [EP()])
        with pytest.raises(RegistryError, match="broken"):
            Registry.from_entry_points()
