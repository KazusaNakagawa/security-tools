from pathlib import Path

import pytest

from alertcheck.config.scope import ConfigError, ScopeConfig, load_scope

VALID = """
organization: Example Inc.
authorization:
  confirmed: true
  approver: IT dept
  confirmed_at: 2026-10-17
targets:
  domains: [example.co.jp]
  urls: [https://shop.example.co.jp/]
  hosts: [203.0.113.10]
  cidrs: [203.0.113.0/28]
exclude: [https://shop.example.co.jp/checkout/]
"""


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(text, encoding="utf-8")
    return p


class TestLoadScopeSuccess:
    def test_valid_scope_loads_with_defaults(self, tmp_path):
        scope = load_scope(write(tmp_path, VALID))
        assert scope.organization == "Example Inc."
        assert scope.authorization.confirmed is True
        assert scope.limits.rps_per_host == 5
        assert scope.limits.concurrency == 4
        assert scope.limits.timeout_sec == 10
        assert scope.limits.allow_private_targets is False
        assert scope.active.enabled is False

    def test_domains_are_lowercased_and_trailing_dot_removed(self, tmp_path):
        text = VALID.replace("[example.co.jp]", "[Example.CO.jp.]")
        assert load_scope(write(tmp_path, text)).targets.domains == ["example.co.jp"]

    def test_unconfirmed_authorization_needs_no_approver(self, tmp_path):
        text = "organization: X\nauthorization: {confirmed: false}\n"
        scope = load_scope(write(tmp_path, text))
        assert scope.authorization.confirmed is False
        assert scope.targets.domains == []

    def test_inputs_are_parsed(self, tmp_path):
        text = (
            VALID
            + """
inputs:
  access_logs:
    - {path: "inputs/logs/*.log", format: nginx_combined, site: shop}
  accounts:
    - {path: inputs/accounts/gws.csv, service: google_workspace, mapping: gws}
  deps:
    - {path: inputs/repos/shop}
    - {image: "registry.example/shop:1"}
"""
        )
        scope = load_scope(write(tmp_path, text))
        assert scope.inputs.access_logs[0].format == "nginx_combined"
        assert scope.inputs.deps[1].image == "registry.example/shop:1"


class TestLoadScopeFailure:
    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_scope(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path):
        with pytest.raises(ConfigError, match="YAML"):
            load_scope(write(tmp_path, "organization: [unclosed\n"))

    def test_top_level_not_mapping(self, tmp_path):
        with pytest.raises(ConfigError, match="mapping"):
            load_scope(write(tmp_path, "- a\n- b\n"))

    def test_confirmed_without_approver_is_rejected(self, tmp_path):
        text = VALID.replace("  approver: IT dept\n", "")
        with pytest.raises(ConfigError, match="approver"):
            load_scope(write(tmp_path, text))

    def test_confirmed_without_date_is_rejected(self, tmp_path):
        text = VALID.replace("  confirmed_at: 2026-10-17\n", "")
        with pytest.raises(ConfigError, match="confirmed_at"):
            load_scope(write(tmp_path, text))

    def test_non_http_url_is_rejected(self, tmp_path):
        text = VALID.replace("https://shop.example.co.jp/]", "ftp://shop.example.co.jp/]")
        with pytest.raises(ConfigError, match="targets.urls"):
            load_scope(write(tmp_path, text))

    def test_invalid_ip_is_rejected(self, tmp_path):
        text = VALID.replace("[203.0.113.10]", "[203.0.113.999]")
        with pytest.raises(ConfigError, match="targets.hosts"):
            load_scope(write(tmp_path, text))

    def test_invalid_cidr_is_rejected(self, tmp_path):
        text = VALID.replace("[203.0.113.0/28]", "[203.0.113.0/33]")
        with pytest.raises(ConfigError, match="targets.cidrs"):
            load_scope(write(tmp_path, text))

    def test_invalid_domain_is_rejected(self, tmp_path):
        text = VALID.replace("[example.co.jp]", "[exa mple.co.jp]")
        with pytest.raises(ConfigError, match="targets.domains"):
            load_scope(write(tmp_path, text))

    def test_unknown_key_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="tagrets"):
            load_scope(write(tmp_path, VALID + "tagrets: {}\n"))

    def test_deps_entry_needs_path_or_image(self, tmp_path):
        text = VALID + "inputs:\n  deps:\n    - {}\n"
        with pytest.raises(ConfigError, match="path or image"):
            load_scope(write(tmp_path, text))


class TestLimitsBoundary:
    @pytest.mark.parametrize("rps", [0, -1, 101])
    def test_rps_out_of_range_is_rejected(self, tmp_path, rps):
        with pytest.raises(ConfigError, match="rps_per_host"):
            load_scope(write(tmp_path, VALID + f"limits: {{rps_per_host: {rps}}}\n"))

    @pytest.mark.parametrize("rps", [1, 100])
    def test_rps_at_bounds_is_accepted(self, tmp_path, rps):
        scope = load_scope(write(tmp_path, VALID + f"limits: {{rps_per_host: {rps}}}\n"))
        assert scope.limits.rps_per_host == rps

    def test_concurrency_zero_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="concurrency"):
            load_scope(write(tmp_path, VALID + "limits: {concurrency: 0}\n"))


def test_scope_config_is_constructible_in_code():
    scope = ScopeConfig(organization="X", authorization={"confirmed": False})
    assert scope.exclude == []


class TestExcludeValidation:
    @pytest.mark.parametrize(
        "entry",
        [
            "https://a.example.co.jp/x/",
            "203.0.113.5",
            "203.0.113.0/30",
            "2001:db8::/64",
            "legacy.example.co.jp",
            "1bad.cafe",
        ],
    )
    def test_valid_entries(self, tmp_path, entry):
        text = VALID.replace(
            "exclude: [https://shop.example.co.jp/checkout/]", f'exclude: ["{entry}"]'
        )
        assert entry in load_scope(write(tmp_path, text)).exclude

    @pytest.mark.parametrize(
        "entry",
        [
            "https://a.example.co.jp:99999/",
            "https://a.example.co.jp:abc/",
            "ftp://a.example.co.jp/",
            "203.0.113.999",
            "203.0.113.0/33",
            "not a host",
        ],
    )
    def test_invalid_entries_are_rejected(self, tmp_path, entry):
        text = VALID.replace(
            "exclude: [https://shop.example.co.jp/checkout/]", f'exclude: ["{entry}"]'
        )
        with pytest.raises(ConfigError, match="exclude"):
            load_scope(write(tmp_path, text))


class TestUrlPortValidation:
    @pytest.mark.parametrize("port", ["99999", "abc", "0x1"])
    def test_bad_port_is_rejected(self, tmp_path, port):
        text = VALID.replace("https://shop.example.co.jp/]", f"https://shop.example.co.jp:{port}/]")
        with pytest.raises(ConfigError, match="targets.urls"):
            load_scope(write(tmp_path, text))

    def test_explicit_valid_port(self, tmp_path):
        text = VALID.replace("https://shop.example.co.jp/]", "https://shop.example.co.jp:8443/]")
        assert load_scope(write(tmp_path, text)).targets.urls == [
            "https://shop.example.co.jp:8443/"
        ]


class TestDuplicateKeys:
    def test_duplicate_top_level_key_is_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="duplicate key 'organization'"):
            load_scope(write(tmp_path, VALID + "organization: Other\n"))

    def test_duplicate_nested_key_is_rejected(self, tmp_path):
        text = VALID.replace("  confirmed: true\n", "  confirmed: true\n  confirmed: false\n")
        with pytest.raises(ConfigError, match="duplicate key 'confirmed'"):
            load_scope(write(tmp_path, text))
