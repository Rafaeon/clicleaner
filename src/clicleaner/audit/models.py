"""Modelos de achados de auditoria."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class Finding:
    check_id: str
    category: str
    severity: Severity
    title: str
    detail: str
    evidence: str = ""
    recommendation: str = ""

    def key(self) -> tuple[str, str]:
        return (self.check_id, self.title)


@dataclass(slots=True)
class CheckResult:
    check_id: str
    name: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_reason: str | None = None
    scanned: int = 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])


@dataclass(slots=True)
class AuditReport:
    results: list[CheckResult]
    started_at: datetime
    finished_at: datetime | None = None
    hostname: str = ""

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    def count_by_severity(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for f in self.all_findings:
            counts[f.severity] += 1
        return counts


def new_report() -> AuditReport:
    import socket

    return AuditReport(
        results=[],
        started_at=datetime.now(UTC),
        hostname=socket.gethostname(),
    )
