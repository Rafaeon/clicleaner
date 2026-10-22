"""Modelos do caçador de resíduos."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class ResidueKind(StrEnum):
    FOLDER = "folder"
    UNINSTALL_ENTRY = "uninstall_entry"
    SERVICE = "service"
    TASK = "task"
    STARTUP = "startup"
    DRIVER = "driver"


@dataclass(slots=True)
class ResidueItem:
    kind: ResidueKind
    name: str
    path: str
    detail: str = ""
    size_bytes: int = 0
    safe_to_delete: bool = True
    note: str = ""

    @property
    def location(self) -> str:
        return self.path


@dataclass(slots=True)
class ResidueReport:
    items: list[ResidueItem] = field(default_factory=list)
    scanned_folders: int = 0
    scanned_entries: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    hostname: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(i.size_bytes for i in self.items)

    @property
    def deletable_bytes(self) -> int:
        return sum(i.size_bytes for i in self.items if i.safe_to_delete)

    def by_kind(self) -> dict[ResidueKind, list[ResidueItem]]:
        out: dict[ResidueKind, list[ResidueItem]] = {}
        for item in self.items:
            out.setdefault(item.kind, []).append(item)
        return out


def new_report() -> ResidueReport:
    import socket

    return ResidueReport(
        items=[],
        hostname=socket.gethostname(),
    )
