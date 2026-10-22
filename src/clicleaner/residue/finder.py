"""Orquestrador do caçador de resíduos."""

from __future__ import annotations

from datetime import UTC, datetime

from clicleaner.residue.collectors import (
    find_broken_services,
    find_broken_startup,
    find_broken_tasks,
    find_folder_residues,
    find_orphan_uninstall_entries,
)
from clicleaner.residue.models import (
    ResidueItem,
    ResidueKind,
    ResidueReport,
    new_report,
)


def run_residue_scan(
    *,
    only: set[str] | None = None,
    exclude: set[str] | None = None,
) -> ResidueReport:
    report = new_report()
    wanted = only or {"folders", "uninstall", "services", "tasks", "startup"}
    if exclude:
        wanted -= exclude

    if "folders" in wanted:
        items, scanned, errors = find_folder_residues()
        report.items.extend(items)
        report.scanned_folders += scanned
        report.errors.extend(errors)

    if "uninstall" in wanted:
        items, scanned, errors = find_orphan_uninstall_entries()
        report.items.extend(items)
        report.scanned_entries += scanned
        report.errors.extend(errors)

    if "services" in wanted:
        items, errors = find_broken_services()
        report.items.extend(items)
        report.errors.extend(errors)

    if "tasks" in wanted:
        items, errors = find_broken_tasks()
        report.items.extend(items)
        report.errors.extend(errors)

    if "startup" in wanted:
        items, errors = find_broken_startup()
        report.items.extend(items)
        report.errors.extend(errors)

    # Ordena: maiores pastas primeiro, depois por tipo
    report.items.sort(
        key=lambda i: (
            0 if i.safe_to_delete else 1,
            -i.size_bytes,
            i.kind.value,
            i.name.lower(),
        )
    )
    report.finished_at = datetime.now(UTC)
    return report


def format_size(n: int) -> str:
    from clicleaner.clean.cleaner import human_bytes

    return human_bytes(n)


__all__ = [
    "ResidueItem",
    "ResidueKind",
    "ResidueReport",
    "format_size",
    "run_residue_scan",
]
