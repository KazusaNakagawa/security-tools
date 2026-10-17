from alertcheck.core.registry import Registry


def test_network_checks_are_registered():
    reg = Registry.from_entry_points()
    ids = {c.id for c in reg.all()}
    assert {
        "tls",
        "http.headers",
        "http.cookies",
        "http.exposure",
        "http.errors",
        "vuln.version",
        "vuln.templates",
        "deps",
    } <= ids
    assert all(not c.active for c in reg.all())
    assert {c.id for c in reg.all() if c.group == "files"} == {"deps"}
    reg.stages()  # no unknown dependencies or cycles
