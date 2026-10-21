import datetime as dt

import pytest

from alertcheck.checks.files.log_analysis import (
    LogStats,
    coverage_days,
    load_signatures,
    match_signatures,
    zscore_anomalies,
)
from alertcheck.checks.files.log_parser import LogRecord

TODAY = dt.date(2026, 10, 21)


def rec(day, status=200, ip="198.51.100.1", path="/", ua="Mozilla", method="GET"):
    return LogRecord(
        ts=dt.datetime(2026, day // 100, day % 100, 12, tzinfo=dt.UTC),
        client_ip=ip,
        method=method,
        path=path,
        status=status,
        bytes=1,
        user_agent=ua,
    )


class TestSignatures:
    def test_bundled_signatures_compile(self):
        sigs = load_signatures()
        assert any(s.id == "sqli_union" for s in sigs)

    @pytest.mark.parametrize(
        "path",
        [
            "/?id=1 UNION SELECT x",
            "/?id=1%20union%20select",
            "/../../etc/passwd",
            "/a?x=${jndi:ldap://e.test/a}",
            "/?q=<script>alert(1)</script>",
        ],
    )
    def test_malicious_paths_match(self, path):
        assert match_signatures(path, "UA")

    def test_scanner_ua_matches(self):
        hits = match_signatures("/", "sqlmap/1.7")
        assert any(h.target == "ua" for h in hits)

    def test_benign_request_does_not_match(self):
        assert match_signatures("/products?category=shoes&sort=price", "Mozilla/5.0") == []


class TestCoverage:
    def test_span_and_recent_window(self):
        records = [rec(1001), rec(1015), rec(1021)]
        cov = coverage_days([r.ts for r in records], today=TODAY)
        assert cov.oldest == dt.date(2026, 10, 1) and cov.newest == dt.date(2026, 10, 21)
        assert cov.recent_span_days == 21

    def test_30_but_not_90(self):
        cov = coverage_days(
            [rec(d // 100 * 100 + d % 100).ts for d in range(911, 912)]
            + [dt.datetime(2026, 9, 12, tzinfo=dt.UTC), dt.datetime(2026, 10, 21, tzinfo=dt.UTC)],
            today=TODAY,
        )
        assert cov.covers_30 and not cov.covers_90

    def test_empty(self):
        cov = coverage_days([], today=TODAY)
        assert cov.oldest is None and not cov.covers_30


class TestZscore:
    def _series(self, n, value=100):
        start = dt.date(2026, 9, 1)
        return {start + dt.timedelta(days=i): value for i in range(n)}

    def test_detects_spike(self):
        daily = self._series(30)
        spike_day = dt.date(2026, 9, 1) + dt.timedelta(days=29)
        daily[spike_day] = 100000
        assert spike_day in {a.day for a in zscore_anomalies(daily, threshold=3.0)}

    def test_no_spike(self):
        daily = {d: 100 + i for i, d in enumerate(self._series(30))}
        assert zscore_anomalies(daily, threshold=3.0) == []

    def test_short_baseline_is_skipped(self):
        daily = {dt.date(2026, 10, d): 100 for d in range(1, 15)}
        daily[dt.date(2026, 10, 15)] = 99999
        assert zscore_anomalies(daily, threshold=3.0) == []  # only 7 baseline days


class TestStats:
    def test_accumulate(self):
        stats = LogStats(allowlist=None)
        for r in [
            rec(1015, 200, path="/ok"),
            rec(1015, 500, path="/err"),
            rec(1015, 200, path="/shell.php", ip="203.0.113.9"),
            rec(1015, 200, path="/?id=1 UNION SELECT a", ip="203.0.113.9", ua="sqlmap"),
        ]:
            stats.add(r)
        day = dt.date(2026, 10, 15)
        assert stats.daily_total[day] == 4
        assert stats.daily_5xx[day] == 1
        assert stats.signature_hits  # sqli + scanner UA
        assert stats.top_ip()[0][1] == 2  # 203.0.113.9 twice
        assert ".php" in " ".join(stats.webshell_candidates())


class TestCoverageStale:
    def test_stale_log_does_not_satisfy_recent_window(self):
        old = [dt.datetime(2025, 1, 1, tzinfo=dt.UTC), dt.datetime(2025, 4, 1, tzinfo=dt.UTC)]
        cov = coverage_days(old, today=TODAY)
        assert cov.oldest == dt.date(2025, 1, 1) and cov.newest == dt.date(2025, 4, 1)
        assert not cov.covers_30 and not cov.covers_90

    def test_current_log_reaching_back_90_days(self):
        ts = [dt.datetime.combine(TODAY - dt.timedelta(days=d), dt.time(), dt.UTC) for d in (0, 95)]
        cov = coverage_days(ts, today=TODAY)
        assert cov.covers_30 and cov.covers_90


class TestZscoreZeroDays:
    def test_traffic_collapse_to_zero_is_detected(self):
        start = dt.date(2026, 9, 1)
        daily = {start + dt.timedelta(days=i): 1000 for i in range(30)}
        outage = start + dt.timedelta(days=29)
        del daily[outage]  # zero-traffic day absent from the counter
        anomalies = zscore_anomalies(daily, threshold=3.0, span=(start, outage))
        assert outage in {a.day for a in anomalies}
        assert next(a for a in anomalies if a.day == outage).value == 0
