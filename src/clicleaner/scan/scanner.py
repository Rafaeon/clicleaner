"""Orquestração do scan com VirusTotal."""

from __future__ import annotations

from datetime import UTC, datetime

from clicleaner.scan.config import load_api_key
from clicleaner.scan.hasher import collect_scan_candidates, sha256_file
from clicleaner.scan.models import FileScanResult, ScanReport, VTVerdict
from clicleaner.scan.vt_client import VTClient


def run_scan(
    paths: list[str] | None = None,
    *,
    max_files: int = 25,
    api_key: str | None = None,
) -> ScanReport:
    report = ScanReport()
    key = (api_key or "").strip() or load_api_key()
    report.api_key_set = bool(key)

    if not key:
        report.errors.append(
            "Chave da API do VirusTotal não configurada. "
            "Crie uma gratuita em https://www.virustotal.com/gui/my-apikey "
            "e use: clicleaner scan --set-key SUA_CHAVE "
            "ou defina a variável de ambiente VT_API_KEY."
        )
        return report

    client = VTClient(key)
    candidates = collect_scan_candidates(paths, max_files=max_files)

    if not candidates:
        report.errors.append("Nenhum arquivo encontrado para consultar.")
        report.finished_at = datetime.now(UTC)
        return report

    for path in candidates:
        try:
            digest = sha256_file(path)
            size = path.stat().st_size
        except OSError as exc:
            report.errors.append(f"{path}: {exc}")
            continue

        result = FileScanResult(
            path=str(path),
            sha256=digest,
            size_bytes=size,
        )
        try:
            lookup = client.lookup_hash(digest)
            report.lookups_used += 1
            if lookup is None:
                result.verdict = VTVerdict.UNKNOWN
                result.message = "nunca analisado no VirusTotal"
            else:
                result.verdict = lookup.verdict
                result.malicious = lookup.malicious
                result.suspicious = lookup.suspicious
                result.harmless = lookup.harmless
                result.undetected = lookup.undetected
                result.total_engines = lookup.total_engines
                result.permalink = lookup.permalink
                result.message = (
                    f"{lookup.malicious}/{lookup.total_engines} detectaram"
                    if lookup.total_engines
                    else ""
                )
        except PermissionError as exc:
            report.errors.append(str(exc))
            report.finished_at = datetime.now(UTC)
            return report
        except RuntimeError as exc:
            report.errors.append(f"{path.name}: {exc}")
            result.message = str(exc)

        report.results.append(result)

    report.finished_at = datetime.now(UTC)
    return report


def format_verdict(v: VTVerdict) -> str:
    return {
        VTVerdict.HARMLESS: "[green]harmless[/]",
        VTVerdict.SUSPICIOUS: "[yellow]suspicious[/]",
        VTVerdict.MALICIOUS: "[red]malicious[/]",
        VTVerdict.UNKNOWN: "[dim]unknown[/]",
    }.get(v, v.value)
