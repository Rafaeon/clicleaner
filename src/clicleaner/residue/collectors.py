"""Coletores de resíduos de software no Windows."""

from __future__ import annotations

import csv
import os
from io import StringIO
from pathlib import Path

from clicleaner.audit.collectors import _extract_path, _is_trusted_path, _run_ps
from clicleaner.residue.models import ResidueItem, ResidueKind

# Pastas do sistema que NÃO são resíduo de app.
_SYSTEM_DIRS = {
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "users",
    "perflogs",
    "recovery",
    "system volume information",
    "documents and settings",
    "$recycle.bin",
    "config.msi",
    "msocache",
}

# Subpastas comuns do Windows dentro de Program Files que não são "app órfão".
_KNOWN_PF = {
    "common files",
    "windows defender",
    "windows defender advanced threat protection",
    "windows mail",
    "windows media player",
    "windows nt",
    "windows photo viewer",
    "windows portable devices",
    "windows security",
    "windowspowershell",
    "microsoft",
    "microsoft.net",
    "internet explorer",
    "dotnet",
    "nodejs",
    "python",
    "python312",
    "python311",
    "python310",
    "java",
    "git",
    "uv",
    "windowsapps",
    "modmagedon",
    "uninstall information",
    "installshield installation information",
    "reference assemblies",
}

# Pastas de runtime/sistema em LOCALAPPDATA/APPDATA/ProgramData que não são resíduo.
_KNOWN_APPDATA = {
    "packages",
    "microsoft",
    "temp",
    "tempo",
    "caches",
    "d3dscache",
    "connecteddevicesplatform",
    "crashdumps",
    "devhome",
    "dsc",
    "elevateddiagnostics",
    "fontcache",
    "group policy",
    "history",
    "mozilla",
    "nvidia corporation",
    "nvidia",
    "oracle",
    "peerdistrepub",
    "pip",
    "powerautomate",
    "programs",
    "publishers",
    "usoshared",
    "uspshared",
    "usoprivate",
    "vaults",
    "virtualstore",
    "yarn",
}

# Ferramentas legítimas de ISO/Windows customizado (ex.: Ghost Spectre).
_KNOWN_ROOT_TOOLS = {
    "ghost toolbox",
    "ghosttoolbox",
    "ghost spectre",
    "ghostspectre",
    "gamingos",
    "atlasos",
    "atlas",
    "windows-ameliorated",
    "ameliorated",
    "nano11",
    "revios",
    "revi-os",
    "tiny11",
    "tiny10",
}

_MAX_RECENT_DAYS = 45


def _is_recently_used(path: Path, days: int = _MAX_RECENT_DAYS) -> bool:
    """True se algum arquivo da pasta foi modificado recentemente."""
    import time

    cutoff = time.time() - days * 86400
    try:
        st = path.stat()
        if st.st_mtime >= cutoff:
            return True
        n = 0
        for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
            for name in files:
                fp = Path(root) / name
                try:
                    if fp.stat().st_mtime >= cutoff:
                        return True
                except OSError:
                    continue
                n += 1
                if n > 200:
                    return False
    except OSError:
        return False
    return False


def _referenced_by_service(cmd_path: str) -> bool:
    """Se algum serviço automático aponta para esta pasta/arquivo."""
    if not cmd_path:
        return False
    out = _run_ps(
        "Get-CimInstance Win32_Service | Select-Object PathName | ConvertTo-Csv -NoTypeInformation",
        timeout=30.0,
    )
    return cmd_path.lower() in (out or "").lower()


def _dir_size(path: Path, limit_files: int = 50_000) -> int:
    total = 0
    n = 0
    try:
        for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
            for name in files:
                fp = Path(root) / name
                try:
                    total += fp.stat().st_size
                except OSError:
                    continue
                n += 1
                if n >= limit_files:
                    return total
    except OSError:
        return 0
    return total


def _looks_like_app_folder(path: Path) -> bool:
    """Heurística: contém binários/exe/dll ou nome 'de programa'."""
    if not path.is_dir():
        return False
    try:
        entries = list(path.iterdir())
    except OSError:
        return False
    if not entries:
        return False

    markers = {".exe", ".dll", ".sys", ".ini", ".json", ".xml", ".txt", ".log", ".dat"}
    names = {p.name.lower() for p in entries}
    suffixes = {p.suffix.lower() for p in entries if p.is_file()}

    if ".exe" in suffixes or ".dll" in suffixes:
        return True
    # pastas com subpastas típicas de app
    if any(
        n in names for n in ("bin", "data", "logs", "config", "resources", "plugins")
    ):
        return True
    return bool(suffixes & markers and len(entries) >= 2)


def _installed_names() -> set[str]:
    """Nomes de DisplayName + InstallLocation de entradas de desinstalação."""
    names: set[str] = set()
    try:
        import winreg
    except ImportError:
        return names

    keys = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ]
    for hive, sub in keys:
        try:
            with winreg.OpenKey(hive, sub) as root:
                i = 0
                while True:
                    try:
                        subname = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(root, subname) as k:
                            for value_name in (
                                "DisplayName",
                                "InstallLocation",
                                "DisplayIcon",
                            ):
                                try:
                                    val, _ = winreg.QueryValueEx(k, value_name)
                                except OSError:
                                    continue
                                val = str(val).strip().strip('"')
                                if not val:
                                    continue
                                names.add(val.lower())
                                # nome da pasta
                                p = _extract_path(val) or val
                                try:
                                    names.add(Path(p).name.lower())
                                except (OSError, ValueError):
                                    continue
                    except OSError:
                        continue
        except OSError:
            continue
    return names


def find_folder_residues() -> tuple[list[ResidueItem], int, list[str]]:
    """Pastas em locais comuns que parecem sobras de software desinstalado."""
    items: list[ResidueItem] = []
    errors: list[str] = []
    installed = _installed_names()

    roots = [
        Path("C:\\"),
        Path(r"C:\Program Files"),
        Path(r"C:\Program Files (x86)"),
        Path(r"C:\ProgramData"),
        Path(os.environ.get("LOCALAPPDATA", "")),
        Path(os.environ.get("APPDATA", "")),
    ]

    scanned = 0
    for root in roots:
        if not root or not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError as exc:
            errors.append(f"{root}: {exc}")
            continue

        for child in children:
            if not child.is_dir():
                continue
            scanned += 1
            name_l = child.name.lower()
            if name_l in _SYSTEM_DIRS or name_l.startswith("."):
                continue
            is_pf = root in {
                Path(r"C:\Program Files"),
                Path(r"C:\Program Files (x86)"),
            }
            is_user = root in {
                Path(os.environ.get("LOCALAPPDATA", "")),
                Path(os.environ.get("APPDATA", "")),
            }
            is_programdata = root == Path(r"C:\ProgramData")
            is_drive_root = root == Path("C:\\")

            if is_pf and name_l in _KNOWN_PF:
                continue
            if (is_user or is_programdata) and name_l in _KNOWN_APPDATA:
                continue
            # Ferramentas de Windows customizado (Ghost Spectre, AtlasOS…)
            if is_drive_root and name_l in _KNOWN_ROOT_TOOLS:
                continue

            # Não sinalizar se o nome aparece em apps instalados
            if name_l in installed or any(name_l in n for n in installed):
                continue

            if not _looks_like_app_folder(child):
                continue

            # Em C:\ raiz, só pastas que realmente parecem app/portable
            if is_drive_root and name_l in {
                "intel",
                "amd",
                "nvidia",
                "perflogs",
                "python",
                "node_modules",
                "users",
                "windows",
                "program files",
                "program files (x86)",
                "programdata",
            }:
                continue

            # Em uso recente → provavelmente não é resíduo órfão
            if _is_recently_used(child):
                continue

            size = _dir_size(child)
            # Em Program Files, se o serviço referencia a pasta, não é resíduo
            if is_pf and _referenced_by_service(str(child)):
                continue

            note = ""
            safe = True
            if size == 0:
                note = "pasta vazia ou quase"
            elif is_drive_root:
                note = "provável app portable / resíduo na raiz"
            elif is_pf:
                safe = False
                note = (
                    "em Program Files sem entrada de desinstalação — "
                    "confirme antes de apagar"
                )
            elif is_user or is_programdata:
                # Config/cache de app: pode apagar se o programa foi desinstalado,
                # mas se o app ainda existe isso pode resetar preferências.
                safe = False
                note = (
                    "parece pasta de app/cache — apague só se o programa "
                    "já foi desinstalado"
                )
            else:
                note = "sem entrada de desinstalação correspondente"

            try:
                entry_count = sum(1 for _ in child.iterdir())
            except OSError:
                entry_count = -1

            items.append(
                ResidueItem(
                    kind=ResidueKind.FOLDER,
                    name=child.name,
                    path=str(child),
                    detail=f"{entry_count} entradas",
                    size_bytes=size,
                    safe_to_delete=safe,
                    note=note,
                )
            )

    return items, scanned, errors


def find_orphan_uninstall_entries() -> tuple[list[ResidueItem], int, list[str]]:
    """Entradas de desinstalação cujo InstallLocation/UninstallString não existe."""
    items: list[ResidueItem] = []
    errors: list[str] = []
    scanned = 0

    try:
        import winreg
    except ImportError:
        return items, scanned, ["winreg indisponível"]

    keys = [
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ]

    for hive, sub in keys:
        try:
            with winreg.OpenKey(hive, sub) as root:
                i = 0
                while True:
                    try:
                        subname = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    scanned += 1
                    try:
                        with winreg.OpenKey(root, subname) as k:

                            def _q(name: str) -> str:
                                try:
                                    val, _ = winreg.QueryValueEx(k, name)
                                    return str(val).strip()
                                except OSError:
                                    return ""

                            display = _q("DisplayName") or subname
                            location = _q("InstallLocation")
                            uninstall = _q("UninstallString")
                            publisher = _q("Publisher")

                            if not location and not uninstall:
                                continue

                            loc_missing = (
                                bool(location)
                                and not Path(location.strip().strip('"')).exists()
                            )
                            uninst_path = _extract_path(uninstall)
                            uninst_missing = (
                                bool(uninst_path) and not Path(uninst_path).exists()
                            )

                            if not loc_missing and not uninst_missing:
                                continue
                            if location and _is_trusted_path(location):
                                continue

                            missing_parts = []
                            if loc_missing:
                                missing_parts.append(
                                    f"InstallLocation não existe: {location}"
                                )
                            if uninst_missing:
                                missing_parts.append(
                                    f"UninstallString não existe: {uninstall}"
                                )

                            items.append(
                                ResidueItem(
                                    kind=ResidueKind.UNINSTALL_ENTRY,
                                    name=display,
                                    path=f"{sub}\\{subname}",
                                    detail="; ".join(missing_parts)
                                    + (
                                        f" | publisher={publisher}" if publisher else ""
                                    ),
                                    size_bytes=0,
                                    safe_to_delete=False,
                                    note=(
                                        "registro órfão — limpe com um desinstalador "
                                        "ou remova a chave manualmente"
                                    ),
                                )
                            )
                    except OSError as exc:
                        errors.append(f"{subname}: {exc}")
        except OSError as exc:
            errors.append(f"{sub}: {exc}")

    return items, scanned, errors


def find_broken_services() -> tuple[list[ResidueItem], list[str]]:
    items: list[ResidueItem] = []
    errors: list[str] = []
    out = _run_ps(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName | "
        "ConvertTo-Csv -NoTypeInformation",
        timeout=40.0,
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        return items, ["não foi possível enumerar serviços"]

    for row in csv.DictReader(StringIO("\n".join(lines))):
        name = (row.get("Name") or "").strip()
        display = (row.get("DisplayName") or "").strip()
        path = (row.get("PathName") or "").strip()
        if not name:
            continue
        cmd_path = _extract_path(path)
        if not cmd_path:
            continue
        if Path(cmd_path).exists():
            continue
        if _is_trusted_path(cmd_path):
            continue
        items.append(
            ResidueItem(
                kind=ResidueKind.SERVICE,
                name=display or name,
                path=cmd_path,
                detail=f"serviço {name} aponta para binário inexistente",
                safe_to_delete=False,
                note="use `sc delete` ou services.msc se o software foi desinstalado",
            )
        )
    return items, errors


def find_broken_tasks() -> tuple[list[ResidueItem], list[str]]:
    items: list[ResidueItem] = []
    errors: list[str] = []
    out = _run_ps(
        "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | "
        "ForEach-Object { "
        "  $a = $_.Actions | Select-Object -First 1; "
        "  [PSCustomObject]@{ "
        "    TaskName = $_.TaskName; "
        "    TaskPath = $_.TaskPath; "
        "    Execute = $a.Execute; "
        "  } "
        "} | ConvertTo-Csv -NoTypeInformation",
        timeout=60.0,
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        return items, ["não foi possível enumerar tarefas"]

    for row in csv.DictReader(StringIO("\n".join(lines))):
        name = (row.get("TaskName") or "").strip()
        path = (row.get("TaskPath") or "").strip()
        execute = (row.get("Execute") or "").strip()
        if not name or not execute:
            continue
        if path.lower().startswith("\\microsoft\\"):
            continue
        cmd_path = _extract_path(execute)
        if not cmd_path or Path(cmd_path).exists():
            continue
        if _is_trusted_path(cmd_path):
            continue
        items.append(
            ResidueItem(
                kind=ResidueKind.TASK,
                name=name,
                path=cmd_path,
                detail=f"tarefa {path}{name} aponta para arquivo inexistente",
                safe_to_delete=False,
                note="remova com taskschd.msc ou Unregister-ScheduledTask",
            )
        )
    return items, errors


def find_broken_startup() -> tuple[list[ResidueItem], list[str]]:
    items: list[ResidueItem] = []
    errors: list[str] = []
    try:
        import winreg
    except ImportError:
        return items, ["winreg indisponível"]

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
    ]
    for hive, sub in run_keys:
        try:
            with winreg.OpenKey(hive, sub) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    cmd_path = _extract_path(str(value))
                    if not cmd_path or Path(cmd_path).exists():
                        continue
                    if _is_trusted_path(cmd_path):
                        continue
                    items.append(
                        ResidueItem(
                            kind=ResidueKind.STARTUP,
                            name=str(name),
                            path=cmd_path,
                            detail=f"Run entry com alvo inexistente: {value}",
                            safe_to_delete=False,
                            note="remova a entrada em msconfig/Regedit se o app sumiu",
                        )
                    )
        except OSError as exc:
            errors.append(f"{sub}: {exc}")

    return items, errors
