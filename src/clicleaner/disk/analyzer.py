"""Analisador de espaço em disco."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class DirSize:
    path: str
    size_bytes: int
    file_count: int = 0


@dataclass(slots=True)
class DiskReport:
    root: str
    total_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0
    top_dirs: list[DirSize] = field(default_factory=list)
    large_files: list[DirSize] = field(default_factory=list)
    scanned_dirs: int = 0
    errors: list[str] = field(default_factory=list)


def _folder_size(path: Path, max_files: int = 200_000) -> tuple[int, int]:
    total = 0
    count = 0
    try:
        for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
            for name in files:
                fp = Path(root) / name
                try:
                    total += fp.stat().st_size
                    count += 1
                except OSError:
                    continue
                if count >= max_files:
                    return total, count
    except OSError:
        pass
    return total, count


def analyze_disk(
    root: str = "C:\\",
    *,
    depth: int = 2,
    top_n: int = 15,
    large_file_mb: int = 200,
) -> DiskReport:
    """Varre `root` agregando tamanho por pasta até `depth` níveis."""
    report = DiskReport(root=root)
    root_path = Path(root)

    try:
        import shutil

        usage = shutil.disk_usage(root_path)
        report.total_bytes = usage.total
        report.used_bytes = usage.used
        report.free_bytes = usage.free
    except OSError as exc:
        report.errors.append(str(exc))

    if not root_path.is_dir():
        report.errors.append(f"raiz inválida: {root}")
        return report

    # Top pastas no primeiro nível
    candidates: list[DirSize] = []
    large: list[DirSize] = []

    def walk_level(path: Path, level: int) -> None:
        try:
            entries = list(path.iterdir())
        except OSError as exc:
            report.errors.append(f"{path}: {exc}")
            return

        report.scanned_dirs += 1
        dirs = [e for e in entries if e.is_dir() and not e.is_symlink()]
        files = [e for e in entries if e.is_file()]

        # Arquivos grandes nesta pasta
        for f in files:
            try:
                st = f.stat()
            except OSError:
                continue
            if st.st_size >= large_file_mb * 1024 * 1024:
                large.append(DirSize(str(f), st.st_size, 1))

        for d in dirs:
            if level >= depth:
                continue
            # Não entra em pastas de sistema pesadas demais se depth > 1
            name_l = d.name.lower()
            if name_l in {"$recycle.bin", "system volume information", "windows"}:
                if level == 0:
                    size, count = _folder_size(d, max_files=50_000)
                    candidates.append(DirSize(str(d), size, count))
                continue

            size, count = _folder_size(d)
            candidates.append(DirSize(str(d), size, count))
            if level + 1 < depth:
                walk_level(d, level + 1)

    walk_level(root_path, 0)

    report.top_dirs = sorted(candidates, key=lambda d: -d.size_bytes)[:top_n]
    report.large_files = sorted(large, key=lambda d: -d.size_bytes)[:top_n]
    return report


def format_size(n: int) -> str:
    from clicleaner.clean.cleaner import human_bytes

    return human_bytes(n)
