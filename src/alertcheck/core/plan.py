"""Execution plan shown by `alertcheck validate` (spec §6.8).

Lists which evidence sources are available and which IPA items would end up
"unverified" because none of their sources is available. The authoritative
verdict logic lives in the judge (issue #6); this is a pre-flight view.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from alertcheck.config.questionnaire import Question
from alertcheck.config.scope import ScopeConfig
from alertcheck.core.models import IPA_ITEMS, Answer
from alertcheck.infra.base import Workspace

# Which IPA items each non-questionnaire source contributes to (spec §4).
SOURCE_ITEMS: dict[str, list[str]] = {
    "network": ["P1-1", "P1-4", "P2-1", "A-1", "A-2", "A-4", "A-6", "D-2", "D-4"],
    "asset_inventory": ["P1-1"],
    "access_logs": ["P1-2", "P1-3", "A-5"],
    "auth_logs": ["P2-2"],
    "accounts": ["P2-3", "A-3", "S-1", "S-2", "S-3"],
    "deps": ["P1-4"],
    "data_inventory": ["P3-1", "P3-2", "D-1"],
    "cloud_aws": ["A-1", "A-5", "S-1", "S-2", "S-4", "S-5", "D-2", "D-4"],
}


@dataclass
class Source:
    kind: str
    available: bool
    ipa_items: list[str]
    detail: str = ""


@dataclass
class Plan:
    sources: list[Source] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unverified_items: list[str] = field(default_factory=list)


def _check_paths(ws: Workspace, paths: list[str], errors: list[str]) -> int:
    """Return how many configured paths matched; record missing ones as errors."""
    found = 0
    for path in paths:
        try:
            matched = (
                ws.glob_inputs(path)
                if any(ch in path for ch in "*?[")
                else ([path] if ws.exists(path) else [])
            )
        except PermissionError:
            errors.append(f"input path escapes the workspace: {path}")
            continue
        if matched:
            found += 1
        else:
            errors.append(f"configured input not found: {path}")
    return found


def build_plan(
    scope: ScopeConfig,
    ws: Workspace,
    answers: list[Answer],
    questions: list[Question],
    *,
    offline: bool = False,
) -> Plan:
    plan = Plan()
    inputs = scope.inputs

    if not scope.authorization.confirmed:
        net = Source("network", False, SOURCE_ITEMS["network"], "authorization.confirmed is false")
    elif offline:
        net = Source("network", False, SOURCE_ITEMS["network"], "--offline")
    elif not any(
        [scope.targets.domains, scope.targets.urls, scope.targets.hosts, scope.targets.cidrs]
    ):
        net = Source("network", False, SOURCE_ITEMS["network"], "no targets defined")
    else:
        net = Source("network", True, SOURCE_ITEMS["network"])
    plan.sources.append(net)

    file_inputs: dict[str, list[str]] = {
        "asset_inventory": [scope.asset_inventory] if scope.asset_inventory else [],
        "access_logs": [i.path for i in inputs.access_logs],
        "auth_logs": [i.path for i in inputs.auth_logs],
        "accounts": [i.path for i in inputs.accounts],
        "deps": [d.path for d in inputs.deps if d.path],
        "data_inventory": [inputs.data_inventory] if inputs.data_inventory else [],
    }
    for kind, paths in file_inputs.items():
        found = _check_paths(ws, paths, plan.errors)
        if kind == "deps":
            found += sum(1 for d in inputs.deps if d.image)
        detail = f"{found} input(s)" if found else "not provided"
        plan.sources.append(Source(kind, found > 0, SOURCE_ITEMS[kind], detail))

    # Inputs that refine other checks but are not sources on their own.
    extras = [scope.inputs.roster, scope.url_allowlist, scope.api_endpoints]
    _check_paths(ws, [p for p in extras if p], plan.errors)

    aws = scope.cloud.aws.enabled and not offline
    plan.sources.append(
        Source("cloud_aws", aws, SOURCE_ITEMS["cloud_aws"], "enabled" if aws else "disabled")
    )

    answered = {a.question_id for a in answers if a.value is not None}
    covered = {i for s in plan.sources if s.available for i in s.ipa_items}
    covered |= {i for q in questions if q.id in answered for i in q.ipa_items}
    plan.unverified_items = sorted(IPA_ITEMS - covered, key=_item_order)
    unanswered = [q.id for q in questions if q.id not in answered]
    if unanswered:
        plan.warnings.append(f"{len(unanswered)} of {len(questions)} questions are unanswered")
    return plan


def _item_order(item: str) -> tuple[int, str]:
    order = "PASDM"
    return (order.index(item[0]), item)
