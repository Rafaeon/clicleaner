"""Execução da limpeza com dry-run, relatório e limites de segurança."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from clicleaner.clean.targets import CleanTarget


@dataclass(slots=True)
class CleanItem:
    path: Path
    size_bytes: int
    is_dir: bool


@dataclass(slots=True)
class TargetResult:
    target: CleanTarget
    items: list[CleanItem] = field(default_factory=list)
    deleted: int = 0
    freed_bytes: int = 0
    errors: list[str] = field(default_factory=list)
    skipped_reason: str | None = None

    @property
    def total_bytes(self) -> int:
        return sum(i.size_bytes for i in self.items)


@dataclass(slots=True)
class CleanReport:
    results: list[TargetResult]
    dry_run: bool
    started_at: datetime
    finished_at: datetime | None = None

    @property
    def total_found_bytes(self) -> int:
        return sum(r.total_bytes for r in self.results)

    @property
    def total_freed_bytes(self) -> int:
        return sum(r.freed_bytes for r in self.results)

    @property
    def total_deleted(self) -> int:
        return sum(r.deleted for r in self.results)


def is_admin() -> bool:
    try:
        return bool(os.getuid() == 0)  # type: ignore[attr-defined]
    except AttributeError:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]


def _dir_size(path: Path) -> int:
    total = 0
    try:
        if path.is_file():
            return path.stat().st_size
        for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
            for name in files:
                fp = Path(root) / name
                try:
                    total += fp.stat().st_size
                except OSError:
                    continue
    except OSError:
        return 0
    return total


def _cutoff(min_age_hours: float) -> datetime | None:
    if min_age_hours <= 0:
        return None
    return datetime.now(UTC) - timedelta(hours=min_age_hours)


def _is_old_enough(path: Path, cutoff: datetime | None) -> bool:
    if cutoff is None:
        return True
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return False
    return mtime <= cutoff


def _is_protected(path: Path, protect: tuple[str, ...]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    for prot in protect:
        prot_path = Path(prot)
        if resolved == prot_path or prot_path in resolved.parents:
            return True
    return False


def collect_items(target: CleanTarget) -> tuple[list[CleanItem], list[str]]:
    items: list[CleanItem] = []
    errors: list[str] = []
    cutoff = _cutoff(target.min_age_hours)

    for path in target.expand():
        if _is_protected(path, target.protect):
            continue

        if any(ch in path.name for ch in "*?[]"):
            parent = path.parent
            if not parent.exists():
                continue
            matches = sorted(parent.glob(path.name))
        elif path.exists():
            matches = [path]
        else:
            continue

        for match in matches:
            if _is_protected(match, target.protect):
                continue
            try:
                if match.is_file():
                    if not _is_old_enough(match, cutoff):
                        continue
                    items.append(CleanItem(match, match.stat().st_size, is_dir=False))
                elif match.is_dir():
                    if target.min_age_hours > 0:
                        # Nunca remove a árvore inteira quando há filtro de
                        # idade — só arquivos individuais antigos.
                        for root, _dirs, files in os.walk(
                            match, onerror=lambda _e: None
                        ):
                            for name in files:
                                fp = Path(root) / name
                                if _is_old_enough(fp, cutoff):
                                    try:
                                        items.append(
                                            CleanItem(
                                                fp, fp.stat().st_size, is_dir=False
                                            )
                                        )
                                    except OSError:
                                        continue
                        continue
                    has_content = False
                    try:
                        has_content = next(match.iterdir(), None) is not None
                    except OSError:
                        has_content = True
                    if has_content:
                        items.append(CleanItem(match, _dir_size(match), is_dir=True))
            except OSError as exc:
                errors.append(f"{match}: {exc}")

    return items, errors


def _safe_unlink(path: Path) -> None:
    if path.is_file() or path.is_symlink():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def run_clean(
    targets: list[CleanTarget],
    *,
    dry_run: bool = True,
    only: set[str] | None = None,
    exclude: set[str] | None = None,
    admin: bool | None = None,
) -> CleanReport:
    if admin is None:
        admin = is_admin()

    started = datetime.now(UTC)
    results: list[TargetResult] = []

    for target in targets:
        if only is not None and target.id not in only:
            continue
        if exclude and target.id in exclude:
            continue

        result = TargetResult(target=target)

        if target.requires_admin and not admin:
            result.skipped_reason = "requer privilégios de administrador"
            results.append(result)
            continue

        items, errors = collect_items(target)
        result.items = items
        result.errors.extend(errors)

        if not dry_run:
            for item in items:
                try:
                    _safe_unlink(item.path)
                    result.deleted += 1
                    result.freed_bytes += item.size_bytes
                except OSError as exc:
                    result.errors.append(f"{item.path}: {exc}")
        else:
            result.deleted = len(items)
            result.freed_bytes = result.total_bytes

        results.append(result)

    return CleanReport(
        results=results,
        dry_run=dry_run,
        started_at=started,
        finished_at=datetime.now(UTC),
    )


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"
