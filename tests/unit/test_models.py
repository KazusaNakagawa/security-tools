import pytest
from pydantic import ValidationError

from alertcheck.core.models import Coverage, Finding, Severity, make_finding_id


def _finding(**overrides):
    base = dict(
        check_id="http.headers",
        kind="csp_missing",
        ipa_items=["A-6"],
        severity=Severity.medium,
        target="https://www.example.co.jp/",
        title="CSP header is missing",
        description="desc",
        evidence={"header": "absent"},
        remediation="Add Content-Security-Policy",
    )
    base.update(overrides)
    return Finding.create(**base)


class TestFindingId:
    def test_same_check_target_kind_gives_same_id_regardless_of_evidence(self):
        a = _finding(evidence={"seen_at": "2026-10-01T00:00:00Z"})
        b = _finding(evidence={"seen_at": "2026-10-17T12:00:00Z"})
        assert a.id == b.id

    def test_id_is_16_hex_chars(self):
        fid = _finding().id
        assert len(fid) == 16
        int(fid, 16)

    def test_different_kind_gives_different_id(self):
        assert _finding(kind="csp_missing").id != _finding(kind="hsts_missing").id

    def test_target_normalization_ignores_host_case_and_root_slash(self):
        a = make_finding_id("http.headers", "HTTPS://WWW.Example.co.jp/", "k")
        b = make_finding_id("http.headers", "https://www.example.co.jp", "k")
        assert a == b

    def test_trailing_slash_on_non_root_path_is_significant(self):
        a = make_finding_id("http.exposure", "https://a.example/admin", "k")
        b = make_finding_id("http.exposure", "https://a.example/admin/", "k")
        assert a != b

    def test_path_case_is_preserved(self):
        a = make_finding_id("http.exposure", "https://a.example/Admin", "k")
        b = make_finding_id("http.exposure", "https://a.example/admin", "k")
        assert a != b

    def test_empty_target_is_allowed(self):
        assert len(make_finding_id("accounts", "", "k")) == 16


class TestFindingValidation:
    def test_unknown_severity_is_rejected(self):
        with pytest.raises(ValidationError):
            _finding(severity="urgent")

    def test_empty_ipa_items_is_rejected(self):
        with pytest.raises(ValidationError):
            _finding(ipa_items=[])

    def test_unknown_ipa_item_format_is_rejected(self):
        with pytest.raises(ValidationError):
            _finding(ipa_items=["X-99"])


class TestSeverity:
    def test_ordering(self):
        assert Severity.critical.rank > Severity.high.rank > Severity.medium.rank
        assert Severity.low.rank > Severity.info.rank


class TestCoverage:
    def test_rejects_unknown_status(self):
        with pytest.raises(ValidationError):
            Coverage(check_id="ports", target="h", status="done")

    def test_defaults_detail_to_empty(self):
        assert Coverage(check_id="ports", target="h", status="executed").detail == ""
