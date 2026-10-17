"""Command line interface (spec §6.8)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Annotated

import typer

from alertcheck.config.questionnaire import load_answers, load_questions, render_answers_template
from alertcheck.config.scope import ConfigError, ScopeConfig, load_scope
from alertcheck.config.templates import INPUT_DIRS, SCOPE_TEMPLATE
from alertcheck.core.context import Context, RunOptions
from alertcheck.core.models import Answer, RunResult, Severity
from alertcheck.core.orchestrator import Orchestrator
from alertcheck.core.plan import build_plan
from alertcheck.core.registry import Registry, RegistryError
from alertcheck.infra.factory import Infra, build_infra

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
        path.write_text(content, encoding="utf-8")
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
        typer.echo(f"  {c.status:<18} {c.check_id} {c.detail}".rstrip())
    typer.echo(f"\nUnverified IPA items ({len(plan.unverified_items)}):")
    typer.echo("  " + (", ".join(plan.unverified_items) or "none"))
    for w in plan.warnings:
        typer.echo(f"warning: {w}")
    if plan.errors:
        for e in plan.errors:
            typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_ERROR)


def _exit_code(run: RunResult) -> int:
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
    """Run the checks."""
    try:
        scope, answers, infra = _load(workspace)
        registry = Registry.from_entry_points()
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
    infra.store.save_run(run)

    typer.echo(f"Run {run.id}: {len(run.findings)} finding(s)")
    for sev in Severity:
        n = sum(1 for f in run.findings if f.severity == sev)
        if n:
            typer.echo(f"  {sev.value:<8} {n}")
    for c in run.coverage:
        if c.status != "executed":
            typer.echo(f"  {c.status:<18} {c.check_id} {c.detail}".rstrip())
    raise typer.Exit(_exit_code(run))


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
    """Update vulnerability databases and Nuclei templates."""
    raise _not_implemented("db update", "issue #4")


@questionnaire_app.command("init")
def questionnaire_init() -> None:
    """Write an empty questionnaire answer file."""
    raise _not_implemented("questionnaire init", "issue #6")


@questionnaire_app.command("show")
def questionnaire_show() -> None:
    """Show questionnaire answers."""
    raise _not_implemented("questionnaire show", "issue #6")
