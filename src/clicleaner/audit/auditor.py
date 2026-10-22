"""Orquestrador da auditoria."""

from __future__ import annotations

from datetime import UTC, datetime

from clicleaner.audit.collectors import COLLECTORS
from clicleaner.audit.models import (
    SEVERITY_ORDER,
    AuditReport,
    CheckResult,
    Finding,
    Severity,
    new_report,
)


def run_audit(
    *,
    only: set[str] | None = None,
    exclude: set[str] | None = None,
) -> AuditReport:
    report = new_report()

    for check_id, (_label, fn) in COLLECTORS.items():
        if only is not None and check_id not in only:
            continue
        if exclude and check_id in exclude:
            continue
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 — auditoria não deve abortar
            result = CheckResult(
                check_id=check_id,
                name=check_id,
                errors=[f"{type(exc).__name__}: {exc}"],
            )
        report.results.append(result)

    report.finished_at = datetime.now(UTC)
    return report


def top_findings(report: AuditReport, limit: int = 20) -> list[Finding]:
    return sorted(
        report.all_findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.title),
    )[:limit]


def severity_style(sev: Severity) -> str:
    return {
        Severity.INFO: "dim",
        Severity.LOW: "green",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bold red",
    }[sev]
