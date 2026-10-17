import json
import re
from importlib.resources import files

import jsonschema
import pytest

from alertcheck.report.render import render_html, render_json
from tests.unit.report.conftest import make_finding

SCHEMA = json.loads(files("alertcheck.report").joinpath("schema.json").read_text(encoding="utf-8"))


class TestJson:
    def test_validates_against_schema(self, make_run):
        data = render_json(make_run())
        jsonschema.validate(data, SCHEMA)
        assert data["schema_version"] == "1.0"
        assert len(data["items"]) == 27

    def test_empty_run_validates(self, make_run):
        jsonschema.validate(render_json(make_run(findings=[], coverage=[])), SCHEMA)

    def test_findings_sorted_by_severity(self, make_run):
        fs = [
            make_finding("a", "low", ["A-6"]),
            make_finding("b", "critical", ["D-2"]),
            make_finding("c", "high", ["A-1"]),
        ]
        data = render_json(make_run(findings=fs))
        assert [f["severity"] for f in data["findings"]] == ["critical", "high", "low"]

    def test_schema_rejects_garbage(self, make_run):
        data = render_json(make_run())
        data["schema_version"] = "2.0"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(data, SCHEMA)

    def test_redact_ips(self, make_run):
        f = make_finding(
            "ip",
            "low",
            ["A-1"],
            evidence={"seen": "from 203.0.113.10 and 2001:db8::1"},
            target="https://203.0.113.10/",
        )
        data = render_json(make_run(findings=[f]), redact_ips=True)
        text = json.dumps(data)
        assert "203.0.113.10" not in text and "2001:db8::1" not in text


class TestHtml:
    def test_no_external_resources(self, make_run):
        html = render_html(make_run())
        assert not re.search(r"<(link|script|img|iframe|object|embed)\b", html, re.I)
        assert not re.search(r"(src|srcset)\s*=\s*[\"']?\s*(https?:)?//", html, re.I)
        assert not re.search(r"@import|url\(\s*[\"']?(https?:)?//", html, re.I)
        assert "Content-Security-Policy" in html and "default-src 'none'" in html

    def test_reference_links_are_plain_anchors(self, make_run):
        html = render_html(make_run())
        assert 'href="https://owasp.org/x"' in html
        assert 'rel="noopener noreferrer"' in html

    def test_untrusted_content_is_escaped(self, make_run):
        payload = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
        f = make_finding(
            "xss",
            "medium",
            ["A-6"],
            title=payload,
            evidence={"log_line": f"GET /?q={payload} HTTP/1.1"},
            target=f"https://a.example/{payload}",
        )
        html = render_html(make_run(findings=[f]))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "<img src=x" not in html

    def test_critical_banner_even_with_high_score(self, make_run):
        from alertcheck.core.models import Answer

        answers = [
            Answer(question_id=q, value="done")
            for q in (
                "q_m1_leadership",
                "q_m2_supply_chain",
                "q_m3_communication",
                "q_d3_access_log",
            )
        ]
        f = make_finding("dump", "critical", ["D-2"], title="DB ダンプが公開されている")
        run = make_run(findings=[f], answers=answers)
        html = render_html(run)
        banner = html.index('class="banner critical"')
        assert banner < html.index("経営サマリー")
        assert "critical の検出が 1 件" in html

    def test_no_banner_without_critical(self, make_run):
        assert 'class="banner critical"' not in render_html(make_run())

    def test_sections_and_content(self, make_run):
        html = render_html(make_run())
        for heading in ("経営サマリー", "IPA 項目別の判定", "検出の詳細", "付録"):
            assert heading in html
        assert "株式会社サンプル" in html
        assert "M-1" in html and "取締役会で承認" in html
        assert "no HTTPS targets" in html  # coverage appendix
        assert html.count('<tr class="item') == 27

    def test_top5_priority(self, make_run):
        fs = [
            make_finding(f"k{i}", sev, ["A-6"], title=f"検出{i}")
            for i, sev in enumerate(["low", "critical", "medium", "high", "info", "high", "medium"])
        ]
        html = render_html(make_run(findings=fs))
        top = html[html.index('id="top5"') : html.index("</ol>", html.index('id="top5"'))]
        assert top.count("<li") == 5
        assert top.index("検出1") < top.index("検出3")  # critical before high
        assert "検出4" not in top  # info never in the top list

    def test_missing_inputs_listed(self, make_run):
        html = render_html(make_run())
        assert "不足している入力" in html
        assert "inputs.deps" in html or "未実装" in html
