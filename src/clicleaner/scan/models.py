"""Modelos do módulo scan (VirusTotal)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class VTVerdict(StrEnum):
    UNKNOWN = "unknown"
    HARMLESS = "harmless"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass(slots=True)
class FileScanResult:
    path: str
    sha256: str
    size_bytes: int
    verdict: VTVerdict = VTVerdict.UNKNOWN
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    permalink: str = ""
    message: str = ""


@dataclass(slots=True)
class ScanReport:
    results: list[FileScanResult] = field(default_factory=list)
    api_key_set: bool = False
    lookups_used: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    errors: list[str] = field(default_factory=list)

    def by_verdict(self) -> dict[VTVerdict, int]:
        counts = dict.fromkeys(VTVerdict, 0)
        for r in self.results:
            counts[r.verdict] += 1
        return counts
