import datetime as dt
import gzip
from pathlib import Path

import pytest

from alertcheck.checks.files.log_parser import parse_lines, parse_stream

FIX = Path(__file__).parents[2] / "fixtures" / "logs"


class TestNginxCombined:
    def test_fields(self):
        records = list(
            parse_lines((FIX / "access.log").read_text().splitlines(), fmt="nginx_combined")
        )
        assert len(records) == 6
        first = records[0]
        assert first.client_ip == "198.51.100.5"
        assert first.method == "GET" and first.path == "/index.html"
        assert first.status == 200 and first.bytes == 1024
        assert first.ts == dt.datetime(
            2026, 10, 15, 9, 0, 1, tzinfo=dt.timezone(dt.timedelta(hours=9))
        )
        assert records[1].user == "alice"

    def test_malformed_lines_are_skipped(self):
        records = list(parse_lines(["garbage", "", "- - -"], fmt="nginx_combined"))
        assert records == []


class TestJsonLines:
    def test_fields(self):
        line = '{"time":"2026-10-15T09:00:01+09:00","remote_addr":"203.0.113.1","request":"GET /a HTTP/1.1","status":"200","body_bytes_sent":"50","http_user_agent":"UA","remote_user":"bob"}'  # noqa: E501
        rec = next(parse_lines([line], fmt="json"))
        assert rec.client_ip == "203.0.113.1" and rec.path == "/a" and rec.status == 200
        assert rec.user == "bob" and rec.bytes == 50

    def test_separate_method_path_keys(self):
        line = '{"timestamp":"2026-10-15T00:00:00Z","client_ip":"1.2.3.4","method":"POST","uri":"/x?y=1","status":404}'  # noqa: E501
        rec = next(parse_lines([line], fmt="json"))
        assert rec.method == "POST" and rec.path == "/x?y=1" and rec.status == 404


class TestAlb:
    def test_fields(self):
        line = (
            "https 2026-10-15T09:00:01.000000Z app/my/abc 203.0.113.5:443 10.0.0.1:80 0.001 0.002 0.003 "  # noqa: E501
            '200 200 100 200 "GET https://example.co.jp:443/path?q=1 HTTP/1.1" "UA-string" ECDHE - -'  # noqa: E501
        )
        rec = next(parse_lines([line], fmt="alb"))
        assert rec.client_ip == "203.0.113.5" and rec.status == 200
        assert rec.path == "/path?q=1" and rec.method == "GET"


def test_parse_stream_reads_gzip(tmp_path):
    gz = tmp_path / "access.log.gz"
    gz.write_bytes(gzip.compress((FIX / "access.log").read_bytes()))
    with gz.open("rb") as f:
        records = list(parse_stream(f, fmt="nginx_combined"))
    assert len(records) == 6


def test_parse_stream_plain(tmp_path):
    with (FIX / "access.log").open("rb") as f:
        assert len(list(parse_stream(f, fmt="nginx_combined"))) == 6


def test_unknown_format():
    with pytest.raises(ValueError, match="unknown log format"):
        list(parse_lines(["x"], fmt="bogus"))


def test_alb_bytes_is_sent_not_received():
    line = (
        "https 2026-10-15T09:00:01.000000Z app/my/abc 203.0.113.5:443 10.0.0.1:80 "  # noqa: E501
        '0.001 0.002 0.003 200 200 100 4096 "GET https://e.co/p HTTP/1.1" "UA" ECDHE - -'
    )
    rec = next(parse_lines([line], fmt="alb"))
    assert rec.bytes == 4096  # sent_bytes (field 11), not received_bytes (field 10 = 100)
