import time

import pytest

from alertcheck.checks.files.log_analysis import LogStats
from alertcheck.checks.files.log_parser import parse_lines


@pytest.mark.perf
def test_one_million_lines_within_budget():
    """Acceptance: ~1M lines processed well within 60s (design budget)."""
    base = '198.51.100.{} - - [15/Oct/2026:12:00:00 +0000] "GET /p/{} HTTP/1.1" 200 10 "-" "Mozilla/5.0"'  # noqa: E501
    lines = [base.format(i % 254 + 1, i) for i in range(1_000_000)]
    stats = LogStats(allowlist=None)
    start = time.perf_counter()
    for record in parse_lines(lines, fmt="nginx_combined"):
        stats.add(record)
    elapsed = time.perf_counter() - start
    assert stats.total == 1_000_000
    assert elapsed < 60, f"took {elapsed:.1f}s"
