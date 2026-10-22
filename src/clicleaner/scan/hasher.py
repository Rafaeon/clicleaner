"""Hash de arquivos para consulta no VirusTotal."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def collect_scan_candidates(
    paths: list[str] | None = None,
    *,
    max_files: int = 25,
    max_size_mb: int = 80,
) -> list[Path]:
    """Monta a lista de arquivos a consultar.

    Sem `paths`, usa atalhos/últimos achados de auditoria (autostart/tasks).
    """
    exts = {".exe", ".dll", ".scr", ".sys", ".ps1", ".bat", ".cmd", ".js", ".vbs"}
    out: list[Path] = []

    if paths:
        for raw in paths:
            p = Path(raw)
            if p.is_file() and p.suffix.lower() in exts:
                out.append(p)
            elif p.is_dir():
                for child in p.rglob("*"):
                    if len(out) >= max_files:
                        break
                    if child.is_file() and child.suffix.lower() in exts:
                        out.append(child)
        return out[:max_files]

    # Padrão: binários citados em autostart/tarefas ainda presentes no disco
    from clicleaner.audit.collectors import check_autostart, check_tasks

    for check in (check_autostart, check_tasks):
        try:
            result = check()
        except Exception:  # noqa: BLE001, S112 — check opcional não pode derrubar o scan
            continue
        for f in result.findings:
            for token in (f.detail, f.evidence):
                for part in str(token).replace("=", " ").split():
                    part = part.strip().strip('"').strip("'")
                    if not part:
                        continue
                    cand = Path(part)
                    try:
                        if (
                            cand.is_file()
                            and cand.suffix.lower() in exts
                            and cand.stat().st_size <= max_size_mb * 1024 * 1024
                            and cand not in out
                        ):
                            out.append(cand)
                    except OSError:
                        continue
                    if len(out) >= max_files:
                        return out
    return out[:max_files]
