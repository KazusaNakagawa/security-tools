"""Command line interface (spec §6.8)."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import Annotated

import httpx
import typer

from alertcheck.adapters.process import ToolFailed, ToolNotFound, run_tool
from alertcheck.config.questionnaire import load_answers, load_questions, render_answers_template
from alertcheck.config.scope import ConfigError, ScopeConfig, load_scope
from alertcheck.config.templates import INPUT_DIRS, SCOPE_TEMPLATE
from alertcheck.core.context import Context, RunOptions
from alertcheck.core.models import Answer, Coverage, Finding, RunResult, Severity
from alertcheck.core.orchestrator import Orchestrator
from alertcheck.core.plan import build_plan
from alertcheck.core.registry import Registry, RegistryError
from alertcheck.infra.factory import Infra, build_infra
from alertcheck.judge.judge import judge, score
from alertcheck.vulndb import cache_dir, update_eol, update_kev

EXIT_OK, EXIT_HIGH, EXIT_CRITICAL, EXIT_ERROR = 0, 1, 2, 3

app = typer.Typer(help="IPA alert (2026-10-09) compliance checker.", no_args_is_help=True)
db_app = typer.Typer(help="Vulnerability database maintenance.")
questionnaire_app = typer.Typer(help="Questionnaire helpers.")
app.add_typer(db_app, name="db")
app.add_typer(questionnaire_app, name="questionnaire")

WorkspaceOpt = Annotated[
    Path,
    typer.Option(
        "--workspace",
        "-w",
        envvar="ALERTCHECK_WORKSPACE",
        help="Directory holding scope.yaml, questionnaire.yaml, inputs/ and out/.",
    ),
]


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(EXIT_ERROR)


def _not_implemented(command: str, where: str) -> typer.Exit:
    return _fail(f"'{command}' is not implemented yet ({where})")


def _load(workspace: Path) -> tuple[ScopeConfig, list[Answer], Infra]:
    scope_path = workspace / "scope.yaml"
    if not scope_path.is_file():
        raise ConfigError(f"{scope_path} not found; run 'alertcheck init' first")
    scope = load_scope(scope_path)
    answers_path = workspace / "questionnaire.yaml"
    answers = load_answers(answers_path) if answers_path.is_file() else []
    infra = build_infra(os.environ.get("ALERTCHECK_RUNTIME", "local"), workspace)
    return scope, answers, infra


def _atomic_write(path: Path, content: str) -> None:
    """Write via a temp file so an interrupted init never leaves a truncated file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _has_errors(coverage: list[Coverage]) -> bool:
    return any(c.status == "error" for c in coverage)


@app.command()
def init(
    workspace: WorkspaceOpt = Path("."),
    force: Annotated[bool, typer.Option(help="Overwrite existing files.")] = False,
) -> None:
    """Create scope.yaml, questionnaire.yaml and input directories."""
    files = {
        "scope.yaml": SCOPE_TEMPLATE,
        "questionnaire.yaml": render_answers_template(load_questions()),
    }
    workspace.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = workspace / name
        if path.exists() and not force:
            typer.echo(f"skip    {path} (exists; use --force to overwrite)")
            continue
        _atomic_write(path, content)
        typer.echo(f"create  {path}")
    for d in INPUT_DIRS:
        (workspace / d).mkdir(parents=True, exist_ok=True)
    typer.echo("Next: edit scope.yaml, then run 'alertcheck validate'.")


@app.command()
def validate(
    workspace: WorkspaceOpt = Path("."),
    offline: Annotated[bool, typer.Option(help="Plan as if run with --offline.")] = False,
) -> None:
    """Validate configuration and inputs and print the execution plan."""
    try:
        scope, answers, infra = _load(workspace)
        registry = Registry.from_entry_points()
        ctx = Context.create(scope=scope, infra=infra, options=RunOptions(offline=offline))
        coverage = Orchestrator(registry, ctx).plan()
    except (ConfigError, RegistryError) as e:
        raise _fail(str(e)) from None

    plan = build_plan(scope, infra.workspace, answers, load_questions(), offline=offline)

    typer.echo(f"Organization: {scope.organization}")
    typer.echo("\nEvidence sources:")
    for s in plan.sources:
        mark = "ok " if s.available else "-- "
        typer.echo(f"  {mark}{s.kind:<16} {s.detail}")
    typer.echo("\nChecks:")
    if not coverage:
        typer.echo("  (no checks registered yet)")
    for c in coverage:
        target = "" if c.target == "*" else f" {c.target}"
        typer.echo(f"  {c.status:<18} {c.check_id}{target} {c.detail}".rstrip())
    typer.echo(f"\nUnverified IPA items ({len(plan.unverified_items)}):")
    typer.echo("  " + (", ".join(plan.unverified_items) or "none"))
    if plan.na_items:
        typer.echo(f"Not applicable (by questionnaire): {', '.join(plan.na_items)}")
    for w in plan.warnings:
        typer.echo(f"warning: {w}")
    errors = plan.errors + [f"{c.check_id}: {c.detail}" for c in coverage if c.status == "error"]
    if errors:
        for e in errors:
            typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_ERROR)


def _exit_code(run: RunResult) -> int:
    # An incomplete run cannot vouch for anything, so execution errors win.
    if _has_errors(run.coverage):
        return EXIT_ERROR
    worst = max((f.severity.rank for f in run.findings), default=-1)
    if worst >= Severity.critical.rank:
        return EXIT_CRITICAL
    if worst >= Severity.high.rank:
        return EXIT_HIGH
    return EXIT_OK


@app.command()
def scan(
    workspace: WorkspaceOpt = Path("."),
    only: Annotated[list[str] | None, typer.Option(help="Run only these checks/groups.")] = None,
    skip: Annotated[list[str] | None, typer.Option(help="Skip these checks/groups.")] = None,
    active: Annotated[
        bool, typer.Option(help="Allow active checks (e.g. login attempts).")
    ] = False,
    offline: Annotated[bool, typer.Option(help="Make no outbound network requests.")] = False,
) -> None:
    """Run the checks.

    Exit code: 0 no critical/high, 1 high, 2 critical, 3 execution error
    (a check failed, so the result is incomplete).
    """
    try:
        scope, answers, infra = _load(workspace)
        registry = Registry.from_entry_points()
        registry.stages()  # surface unknown dependencies / cycles as a config error
    except (ConfigError, RegistryError) as e:
        raise _fail(str(e)) from None
    options = RunOptions(
        active=active and scope.active.enabled, offline=offline, only=only or (), skip=skip or ()
    )
    if active and not scope.active.enabled:
        typer.echo("warning: --active ignored because active.enabled is false in scope.yaml")
    ctx = Context.create(scope=scope, infra=infra, options=options)
    run = asyncio.run(Orchestrator(registry, ctx).run())
    run.answers = answers
    run.items = judge(
        run.findings, run.coverage, answers, available_checks={c.id for c in registry.all()}
    )
    run.score = score(run.items, run.findings)
    infra.store.save_run(run)

    findings = sorted(run.findings, key=lambda f: (-f.severity.rank, f.check_id, f.target))
    results_path = _write_findings(infra, run, findings)

    if run.score.critical:
        typer.echo(f"警告: critical の検出が {run.score.critical} 件あります（最優先で対応）")
    typer.echo(f"Run {run.id}: {len(findings)} finding(s)")
    _echo_score(run)
    for sev in Severity:
        n = sum(1 for f in findings if f.severity == sev)
        if n:
            typer.echo(f"  {sev.value:<8} {n}")
    if findings:
        typer.echo("\nFindings:")
    for f in findings:
        typer.echo(f"  [{f.severity.value}] {f.check_id}  {f.title}")
        typer.echo(f"      {f.target}")
        typer.echo(f"      対策: {f.remediation}")
    if findings:
        typer.echo("")
    for c in run.coverage:
        # partial probe failures must not look like a clean result
        if c.status != "executed" or "probes failed" in c.detail:
            typer.echo(f"  {c.status:<18} {c.check_id} {c.target} {c.detail}".rstrip())
    for w in ctx.guard.warnings:
        typer.echo(f"warning: {w}")
    typer.echo(f"Results: {results_path}")
    raise typer.Exit(_exit_code(run))


_VERDICT_LABELS = {
    "achieved": "達成",
    "partial": "一部達成",
    "not_achieved": "未達",
    "unverified": "未確認",
    "na": "対象外",
}


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f}%"


def _echo_score(run: RunResult) -> None:
    assert run.score is not None
    counts = "  ".join(f"{_VERDICT_LABELS[k]} {v}" for k, v in run.score.counts.items())
    typer.echo(f"  達成率 {_pct(run.score.overall)}  ({counts})")
    for item in run.items:
        if item.mismatch:
            typer.echo(f"  食い違い {item.ipa_item}: {item.rationale}")


def _write_findings(infra: Infra, run: RunResult, findings: list[Finding]) -> str:
    """Interim machine-readable output until the report command (#7) lands."""
    payload = {
        "schema": "alertcheck.findings/0",
        "run": run.model_dump(
            mode="json", include={"id", "started_at", "finished_at", "tool_version", "options"}
        ),
        "score": run.score.model_dump(mode="json") if run.score else None,
        "items": [i.model_dump(mode="json") for i in run.items],
        "findings": [f.model_dump(mode="json") for f in findings],
        "coverage": [c.model_dump(mode="json") for c in run.coverage],
    }
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return infra.workspace.write_output(run.id, "findings.json", data, "application/json")


@app.command()
def report(
    run: Annotated[str | None, typer.Option("--run", help="Run ID (default: latest).")] = None,
    format: Annotated[str, typer.Option(help="Comma-separated: html,json,md,csv.")] = "html,json",
) -> None:
    """Render reports for a run."""
    raise _not_implemented("report", "issue #7")


@app.command()
def diff(run_a: str, run_b: str) -> None:
    """Compare two runs."""
    raise _not_implemented("diff", "phase 2")


@app.command()
def serve() -> None:
    """Start the local Web UI."""
    raise _not_implemented("serve", "phase 2")


@db_app.command("update")
def db_update() -> None:
    """Refresh CISA KEV, endoflife.date data and installed scanners' databases."""
    ok = asyncio.run(_db_update(cache_dir()))
    if not ok:
        raise typer.Exit(EXIT_ERROR)


_TOOL_UPDATES = [
    ["trivy", "image", "--download-db-only", "--quiet"],
    # downloads osv-scanner's local databases used by --offline; scanning an empty dir is enough
    [
        "osv-scanner",
        "scan",
        "source",
        "--offline-vulnerabilities",
        "--download-offline-databases",
        "--recursive",
    ],
    ["nuclei", "-update-templates", "-silent", "-disable-update-check"],
]


async def _db_update(cache: Path) -> bool:
    typer.echo(f"Cache: {cache}")
    ok = True
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for name, update in (("kev", update_kev), ("eol", update_eol)):
            try:
                count = await update(client, cache)
                typer.echo(f"  ok    {name:<12} {count} entries")
            except (httpx.HTTPError, ValueError) as e:
                ok = False
                typer.echo(f"  fail  {name:<12} {e}")
    with tempfile.TemporaryDirectory() as empty:
        for argv in _TOOL_UPDATES:
            full = [*argv, empty] if argv[0] == "osv-scanner" else argv
            try:
                await run_tool(full, timeout=1800, ok_codes=(0, 1, 128))
                typer.echo(f"  ok    {argv[0]}")
            except ToolNotFound:
                typer.echo(f"  skip  {argv[0]:<12} not installed")
            except ToolFailed as e:
                ok = False  # an installed scanner left with stale data is a failure
                typer.echo(f"  fail  {argv[0]:<12} {e}")
    return ok


@questionnaire_app.command("init")
def questionnaire_init(
    workspace: WorkspaceOpt = Path("."),
    force: Annotated[bool, typer.Option(help="Overwrite an existing file.")] = False,
) -> None:
    """Write an empty questionnaire answer file."""
    path = workspace / "questionnaire.yaml"
    if path.exists() and not force:
        typer.echo(f"skip    {path} (exists; use --force to overwrite)")
        return
    workspace.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, render_answers_template(load_questions()))
    typer.echo(f"create  {path}")


@questionnaire_app.command("show")
def questionnaire_show(workspace: WorkspaceOpt = Path(".")) -> None:
    """Show each question with its current answer."""
    questions = load_questions()
    path = workspace / "questionnaire.yaml"
    try:
        answers = {a.question_id: a for a in load_answers(path)} if path.is_file() else {}
    except ConfigError as e:
        raise _fail(str(e)) from None
    answered = sum(1 for a in answers.values() if a.value is not None)
    typer.echo(f"回答済み {answered}/{len(questions)}")
    for q in questions:
        a = answers.get(q.id)
        value = a.value if a and a.value is not None else "未回答"
        typer.echo(f"  {value:<9} {q.id}  [{', '.join(q.ipa_items)}] {q.text}")


@app.command()
def runs(
    run_id: Annotated[str | None, typer.Argument(help="Show this run's IPA item verdicts.")] = None,
    workspace: WorkspaceOpt = Path("."),
) -> None:
    """List stored runs, or show one run's verdicts."""
    try:
        infra = build_infra(os.environ.get("ALERTCHECK_RUNTIME", "local"), workspace)
    except ConfigError as e:
        raise _fail(str(e)) from None
    if run_id is None:
        stored = infra.store.list_runs()
        if not stored:
            typer.echo("no runs yet; run 'alertcheck scan'")
        for r in stored:
            s = r.score
            summary = f"達成率 {_pct(s.overall)} critical {s.critical} high {s.high}" if s else ""
            typer.echo(
                f"  {r.id}  {r.started_at:%Y-%m-%d %H:%M}  {len(r.findings)} findings  {summary}"
            )
        return
    run = infra.store.get_run(run_id)
    if run is None:
        raise _fail(f"run not found: {run_id}")
    typer.echo(f"Run {run.id}  {run.started_at:%Y-%m-%d %H:%M} UTC  {len(run.findings)} finding(s)")
    if run.score:
        _echo_score(run)
    for item in run.items:
        typer.echo(f"  {item.ipa_item:<5} {item.verdict:<13} {item.rationale}")
        for m in item.missing_inputs:
            typer.echo(f"        不足: {m}")
