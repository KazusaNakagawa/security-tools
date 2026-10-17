import pytest

from alertcheck.core.masking import mask_email, mask_env_content, mask_evidence, mask_text


class TestMaskEnvContent:
    def test_values_are_masked_and_keys_kept(self):
        src = "DB_HOST=db.internal\nDB_PASSWORD=s3cr3t\n"
        assert mask_env_content(src) == "DB_HOST=***\nDB_PASSWORD=***\n"

    def test_comments_blank_lines_and_export_are_preserved(self):
        src = "# comment\n\nexport API_KEY='abc'\n"
        assert mask_env_content(src) == "# comment\n\nexport API_KEY=***\n"

    def test_empty_value_stays_empty(self):
        assert mask_env_content("EMPTY=\n") == "EMPTY=\n"

    def test_lines_without_equals_are_masked_entirely(self):
        assert mask_env_content("garbage line") == "***"

    def test_empty_input(self):
        assert mask_env_content("") == ""


class TestMaskEmail:
    def test_keeps_first_char_and_domain(self):
        assert mask_email("yamada@example.co.jp") == "y***@example.co.jp"

    def test_single_char_local_part(self):
        assert mask_email("a@example.com") == "a***@example.com"


class TestMaskText:
    def test_email_in_text(self):
        assert mask_text("contact: yamada@example.co.jp.") == "contact: y***@example.co.jp."

    def test_aws_access_key(self):
        assert mask_text("key AKIAIOSFODNN7EXAMPLE end") == "key AKIA*** end"

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert mask_text(f"token={jwt}") == "token=eyJh***"

    def test_bearer(self):
        assert mask_text("Authorization: Bearer abcdef123456") == "Authorization: Bearer abcd***"

    def test_long_high_entropy_string(self):
        secret = "Zx8kQ2vLp9TnR4wYb7HcM1sJd6FgA3eU"
        assert mask_text(f"x {secret} y") == "x Zx8k*** y"

    def test_long_low_entropy_string_is_kept(self):
        text = "a" * 40
        assert mask_text(text) == text

    def test_ip_addresses_are_not_masked(self):
        assert mask_text("from 203.0.113.10") == "from 203.0.113.10"

    def test_plain_text_unchanged(self):
        assert mask_text("CSP header is missing") == "CSP header is missing"

    def test_31_chars_high_entropy_is_kept(self):
        s = "Zx8kQ2vLp9TnR4wYb7HcM1sJd6FgA3e"
        assert len(s) == 31
        assert mask_text(s) == s


class TestMaskEvidence:
    def test_nested_structures(self):
        evidence = {
            "rows": [{"email": "suzuki@example.com", "count": 3}],
            "header": "Bearer abcdef123456",
            "ok": True,
            "none": None,
        }
        assert mask_evidence(evidence) == {
            "rows": [{"email": "s***@example.com", "count": 3}],
            "header": "Bearer abcd***",
            "ok": True,
            "none": None,
        }

    def test_does_not_mutate_input(self):
        evidence = {"email": "suzuki@example.com"}
        mask_evidence(evidence)
        assert evidence == {"email": "suzuki@example.com"}

    @pytest.mark.parametrize("value", [{}, [], ""])
    def test_empty(self, value):
        assert mask_evidence(value) == value
