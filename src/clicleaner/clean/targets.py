"""Alvos de limpeza segura no Windows."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CleanTarget:
    id: str
    name: str
    description: str
    paths: tuple[str, ...]
    requires_admin: bool = False
    # Só remove arquivos com idade mínima (horas). 0 = sem filtro.
    min_age_hours: float = 0.0
    # Nunca tocar nestas pastas/árvores.
    protect: tuple[str, ...] = field(default_factory=tuple)

    def expand(self) -> list[Path]:
        out: list[Path] = []
        for raw in self.paths:
            p = Path(os.path.expandvars(raw))
            if any(p == Path(prot) or Path(prot) in p.parents for prot in self.protect):
                continue
            out.append(p)
        return out


def _user_profile() -> Path:
    return Path(os.environ.get("USERPROFILE", str(Path.home())))


def _local_app_data() -> Path:
    return Path(
        os.environ.get("LOCALAPPDATA", str(_user_profile() / "AppData" / "Local"))
    )


def _temp_dir() -> Path:
    return Path(os.environ.get("TEMP", str(_local_app_data() / "Temp")))


def build_targets() -> list[CleanTarget]:
    """Cria a lista de alvos com base no ambiente atual."""
    local = _local_app_data()
    temp = _temp_dir()
    profile = _user_profile()

    return [
        CleanTarget(
            id="user-temp",
            name="Temp do usuário",
            description="Arquivos temporários do usuário (%TEMP%)",
            paths=(str(temp),),
            min_age_hours=1.0,
        ),
        CleanTarget(
            id="windows-temp",
            name="Temp do Windows",
            description="C:\\Windows\\Temp (requer admin)",
            paths=(r"C:\Windows\Temp",),
            requires_admin=True,
            min_age_hours=1.0,
        ),
        CleanTarget(
            id="prefetch",
            name="Prefetch",
            description="Cache de prefetch do Windows (requer admin)",
            paths=(r"C:\Windows\Prefetch",),
            requires_admin=True,
            min_age_hours=24.0,
        ),
        CleanTarget(
            id="thumbcache",
            name="Cache de miniaturas",
            description="Thumbnail cache do Explorer",
            paths=(
                str(local / "Microsoft" / "Windows" / "Explorer" / "thumbcache_*.db"),
                str(local / "Microsoft" / "Windows" / "Explorer" / "iconcache_*.db"),
            ),
            min_age_hours=1.0,
        ),
        CleanTarget(
            id="crash-dumps",
            name="Despejos de erro",
            description="Crash dumps e relatórios de erro do Windows",
            paths=(
                str(local / "CrashDumps"),
                str(local / "Microsoft" / "Windows" / "WER" / "ReportArchive"),
                str(local / "Microsoft" / "Windows" / "WER" / "ReportQueue"),
                str(
                    profile
                    / "AppData"
                    / "Local"
                    / "Microsoft"
                    / "Windows"
                    / "WER"
                    / "Temp"
                ),
            ),
        ),
        CleanTarget(
            id="delivery-optimization",
            name="Delivery Optimization",
            description="Cache de atualizações do Windows (Delivery Optimization)",
            paths=(r"C:\Windows\SoftwareDistribution\DeliveryOptimization\Cache",),
            requires_admin=True,
        ),
        CleanTarget(
            id="wu-download",
            name="Windows Update (Download)",
            description="Downloads do Windows Update já aplicados (requer admin)",
            paths=(r"C:\Windows\SoftwareDistribution\Download",),
            requires_admin=True,
            min_age_hours=24.0,
        ),
        CleanTarget(
            id="browser-cache",
            name="Cache de navegadores",
            description="Chrome, Edge, Brave",
            paths=(
                str(local / "Google" / "Chrome" / "User Data" / "Default" / "Cache"),
                str(
                    local / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache"
                ),
                str(local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache"),
                str(
                    local
                    / "Microsoft"
                    / "Edge"
                    / "User Data"
                    / "Default"
                    / "Code Cache"
                ),
                str(
                    local
                    / "BraveSoftware"
                    / "Brave-Browser"
                    / "User Data"
                    / "Default"
                    / "Cache"
                ),
                str(
                    local
                    / "BraveSoftware"
                    / "Brave-Browser"
                    / "User Data"
                    / "Default"
                    / "Code Cache"
                ),
            ),
            min_age_hours=1.0,
        ),
        CleanTarget(
            id="browser-cache-firefox",
            name="Cache do Firefox",
            description="Só a subpasta cache2 de cada perfil do Firefox",
            paths=(
                str(local / "Mozilla" / "Firefox" / "Profiles" / "*" / "cache2"),
                str(local / "Mozilla" / "Firefox" / "Profiles" / "*" / "startupCache"),
            ),
            min_age_hours=1.0,
        ),
        CleanTarget(
            id="recent",
            name="Itens recentes",
            description="Atalhos de itens recentes do Explorer",
            paths=(
                str(
                    profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
                ),
            ),
        ),
        CleanTarget(
            id="dev-caches",
            name="Caches de dev",
            description="pip, uv, npm, yarn (se existirem)",
            paths=(
                str(local / "pip" / "cache"),
                str(local / "uv" / "cache"),
                str(local / "npm-cache"),
                str(profile / ".npm" / "_cacache"),
                str(profile / ".cache" / "yarn"),
            ),
        ),
        CleanTarget(
            id="windows-error-reporting",
            name="Windows Error Reporting",
            description="Arquivos .wer e minidumps antigos",
            paths=(r"C:\ProgramData\Microsoft\Windows\WER",),
            requires_admin=True,
            min_age_hours=24.0,
        ),
    ]
