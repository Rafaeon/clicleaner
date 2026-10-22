"""Status do Windows Defender (somente leitura)."""

from __future__ import annotations

from dataclasses import dataclass

from clicleaner.audit.collectors import _run_ps


@dataclass(slots=True)
class DefenderStatus:
    available: bool = False
    real_time: bool | None = None
    tamper_protection: bool | None = None
    behavior_monitor: bool | None = None
    signature_age_days: int | None = None
    signature_version: str = ""
    quick_scan_end: str = ""
    full_scan_end: str = ""
    antivirus_enabled: bool | None = None
    antispyware_enabled: bool | None = None
    cloud_protection: bool | None = None
    error: str = ""

    @property
    def healthy(self) -> bool:
        if not self.available:
            return False
        if self.real_time is False or self.antivirus_enabled is False:
            return False
        return not (self.signature_age_days is not None and self.signature_age_days > 7)


def _parse_bool(raw: str) -> bool | None:
    v = (raw or "").strip().lower()
    if v in {"true", "1", "enabled", "on"}:
        return True
    if v in {"false", "0", "disabled", "off"}:
        return False
    return None


def get_defender_status() -> DefenderStatus:
    status = DefenderStatus()

    prefs = _run_ps(
        "try { $p = Get-MpComputerStatus | Select-Object "
        "RealTimeProtectionEnabled,TamperProtectionSource,BehaviorMonitorEnabled,"
        "AntivirusSignatureAge,AntivirusSignatureVersion,QuickScanEndTime,FullScanEndTime,"
        "AntivirusEnabled,AntispywareEnabled "
        "| ConvertTo-Csv -NoTypeInformation; $p } catch { 'ERROR:' + $_.Exception.Message }",
        timeout=30.0,
    )
    if prefs.strip().startswith("ERROR:"):
        status.error = prefs.strip().replace("ERROR:", "", 1)
        return status

    lines = [ln for ln in prefs.splitlines() if ln.strip()]
    if len(lines) < 2:
        # Pode não ter o cmdlet (ex.: Defender removido em ISO custom)
        status.error = (
            "Get-MpComputerStatus indisponível (Defender ausente ou desativado)"
        )
        return status

    import csv
    from io import StringIO

    row = next(csv.DictReader(StringIO("\n".join(lines))), None)
    if not row:
        status.error = "não foi possível interpretar o status do Defender"
        return status

    status.available = True
    status.real_time = _parse_bool(row.get("RealTimeProtectionEnabled", ""))
    status.behavior_monitor = _parse_bool(row.get("BehaviorMonitorEnabled", ""))
    status.antivirus_enabled = _parse_bool(row.get("AntivirusEnabled", ""))
    status.antispyware_enabled = _parse_bool(row.get("AntispywareEnabled", ""))

    tamper = (row.get("TamperProtectionSource") or "").strip()
    status.tamper_protection = (
        None if not tamper else tamper.lower() not in {"none", "disabled"}
    )

    age = (row.get("AntivirusSignatureAge") or "").strip()
    if age.isdigit():
        status.signature_age_days = int(age)

    status.signature_version = (row.get("AntivirusSignatureVersion") or "").strip()
    status.quick_scan_end = (row.get("QuickScanEndTime") or "").strip()
    status.full_scan_end = (row.get("FullScanEndTime") or "").strip()

    cloud = _run_ps(
        "try { (Get-MpPreference).MAPSReporting } catch { '' }",
        timeout=20.0,
    ).strip()
    # 0=disabled, 1=basic, 2=advanced
    status.cloud_protection = cloud not in {"0", ""}

    return status


def render_defender_status(status: DefenderStatus) -> list[str]:
    """Linhas simples para o CLI (sem rich)."""
    if not status.available:
        return [f"Indisponível: {status.error or 'Defender não encontrado'}"]

    def yn(v: bool | None) -> str:
        if v is None:
            return "?"
        return "sim" if v else "NÃO"

    lines = [
        f"Proteção em tempo real: {yn(status.real_time)}",
        f"Antivírus ativo:        {yn(status.antivirus_enabled)}",
        f"Anti-spyware:           {yn(status.antispyware_enabled)}",
        f"Monitor de comportamento: {yn(status.behavior_monitor)}",
        f"Proteção contra adulteração: {yn(status.tamper_protection)}",
        f"Proteção em nuvem:      {yn(status.cloud_protection)}",
        f"Idade das assinaturas:  {status.signature_age_days if status.signature_age_days is not None else '?'} dia(s)",
        f"Versão da assinatura:   {status.signature_version or '—'}",
        f"Último scan rápido:     {status.quick_scan_end or '—'}",
        f"Último scan completo:   {status.full_scan_end or '—'}",
    ]
    return lines
