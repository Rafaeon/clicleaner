"""Coletores de auditoria para Windows.

Cada coletor retorna `CheckResult`. Não instala nada e não altera o sistema.
"""

from __future__ import annotations

import csv
import os
import re
import subprocess
from collections.abc import Callable
from io import StringIO
from pathlib import Path

from clicleaner.audit.models import CheckResult, Finding, Severity

_TRUSTED_PUBLISHERS = (
    "Microsoft Windows",
    "Microsoft Corporation",
    "Microsoft Windows Publisher",
)

_TRUSTED_PATH_PREFIXES = (
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\WinSxS",
    r"C:\Program Files\Windows Defender",
    r"C:\Program Files\WindowsApps",
    r"C:\Program Files (x86)\Microsoft",
    r"C:\Program Files\Microsoft",
)

_WINDOWS_BINARIES = {
    "explorer.exe",
    "securityhealthsystray.exe",
    "securityhealthservice.exe",
    "ctfmon.exe",
    "sihost.exe",
    "taskhostw.exe",
    "userinit.exe",
    "logonui.exe",
    "dwm.exe",
}

_COMMON_PROCESSES = {
    "svchost",
    "system",
    "lsass",
    "services",
    "wininit",
    "dwm",
    "explorer",
    "code",
    "python",
    "pythonw",
    "node",
    "java",
    "sqlservr",
    "postgres",
    "mysqld",
    "docker",
    "vmware",
    "vmmem",
}


def _is_trusted_path(path: str) -> bool:
    low = path.lower().strip('"')
    name = low.rsplit("\\", 1)[-1]
    if name in _WINDOWS_BINARIES:
        return True
    for pref in _TRUSTED_PATH_PREFIXES:
        if low.startswith(pref.lower()):
            return True
    return False


def _in_program_files(path: str) -> bool:
    low = (path or "").lower()
    return low.startswith(("c:\\program files", "c:\\program files (x86)"))


def _run_ps(script: str, timeout: float = 30.0) -> str:
    proc = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        timeout=timeout,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
    return proc.stdout or ""


def _ps_signature_ok(path: str) -> bool | None:
    """True = assinado e válido, False = inválido/não assinado, None = indeterminado."""
    escaped = path.replace("'", "''")
    out = _run_ps(
        f"$s = Get-AuthenticodeSignature -FilePath '{escaped}'; $s.Status.ToString()",
        timeout=20.0,
    )
    status = (out or "").strip().splitlines()
    if not status:
        return None
    val = status[0].strip()
    if val == "Valid":
        return True
    if val in {"NotSigned", "HashMismatch", "NotTrusted", "UnknownError"}:
        return False
    return None


def _expand_env(path: str) -> str:
    return os.path.expandvars(path.strip().strip('"'))


def _extract_path(command: str) -> str:
    """Extrai um caminho de arquivo de uma linha de comando."""
    command = _expand_env(command.strip())
    m = re.match(r'^"([^"]+)"', command)
    if m:
        return _expand_env(m.group(1))
    m = re.match(r"^(\S+\.(?:exe|com|bat|cmd|ps1|vbs|js))\b", command, re.IGNORECASE)
    if m:
        return _expand_env(m.group(1))
    if command.lower().endswith(
        (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk")
    ):
        return _expand_env(command.split(" /")[0].split(" -")[0])
    return ""


# ---------------------------------------------------------------------------
# 1. Autostart
# ---------------------------------------------------------------------------


def check_autostart() -> CheckResult:
    result = CheckResult(check_id="autostart", name="Autostart (Run/Startup)")
    entries: list[tuple[str, str, str]] = []

    try:
        import winreg
    except ImportError:
        result.skipped_reason = "winreg indisponível (não-Windows)"
        return result

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
    ]

    for hive, sub in run_keys:
        label = ("HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM") + "\\" + sub
        try:
            with winreg.OpenKey(hive, sub) as key:
                i = 0
                while True:
                    try:
                        name, value, _typ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    entries.append((label, name, str(value)))
                    i += 1
        except OSError:
            continue

    startup_dirs = [
        Path.home()
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup",
        Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for d in startup_dirs:
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.suffix.lower() in {".lnk", ".exe", ".bat", ".cmd", ".ps1", ".vbs"}:
                entries.append((str(d), f.name, str(f)))

    for _hive, sub, value_name in (
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
        ),
    ):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub) as key:
                val, _ = winreg.QueryValueEx(key, value_name)
                entries.append((f"HKLM\\{sub}", value_name, str(val)))
        except OSError:
            continue

    result.scanned = len(entries)
    for location, name, command in entries:
        cmd_path = _extract_path(command)
        trusted = _is_trusted_path(cmd_path) if cmd_path else False
        in_pf = _in_program_files(cmd_path)
        sig_ok: bool | None = None
        if cmd_path and Path(cmd_path).is_file():
            sig_ok = _ps_signature_ok(cmd_path)

        if trusted and sig_ok in (True, None):
            severity = Severity.INFO
            title = f"Autostart de sistema: {name}"
            rec = ""
        elif sig_ok is False:
            severity = Severity.HIGH
            title = f"Autostart sem assinatura válida: {name}"
            rec = (
                "Confirme se o programa é esperado; remova a entrada se não reconhecer."
            )
        elif sig_ok is True:
            severity = Severity.LOW
            title = f"Autostart de terceiro: {name}"
            rec = "Revise se ainda é necessário."
        elif in_pf:
            severity = Severity.LOW
            title = f"Autostart em Program Files: {name}"
            rec = "Programa instalado — confirme se precisa iniciar com o Windows."
        elif not trusted:
            severity = Severity.MEDIUM
            title = f"Autostart não confiável/sem caminho de sistema: {name}"
            rec = "Verifique o fabricante e a necessidade desta entrada."
        else:
            severity = Severity.INFO
            title = f"Autostart: {name}"
            rec = ""

        result.findings.append(
            Finding(
                check_id="autostart",
                category="autostart",
                severity=severity,
                title=title,
                detail=command,
                evidence=f"{location} :: {name} = {command}",
                recommendation=rec,
            )
        )

    return result


# ---------------------------------------------------------------------------
# 2. Serviços
# ---------------------------------------------------------------------------


def check_services() -> CheckResult:
    result = CheckResult(check_id="services", name="Serviços de terceiros")
    out = _run_ps(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName | "
        "ConvertTo-Csv -NoTypeInformation",
        timeout=40.0,
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        result.skipped_reason = "não foi possível enumerar serviços"
        return result

    rows = list(csv.DictReader(StringIO("\n".join(lines))))
    result.scanned = len(rows)

    for row in rows:
        name = (row.get("Name") or "").strip()
        display = (row.get("DisplayName") or "").strip()
        state = (row.get("State") or "").strip()
        start_mode = (row.get("StartMode") or "").strip()
        path = (row.get("PathName") or "").strip()

        if not name or start_mode not in {"Auto", "Automatic"}:
            continue

        cmd_path = _extract_path(path)
        trusted = _is_trusted_path(cmd_path) if cmd_path else False
        in_pf = _in_program_files(cmd_path)
        if trusted or ("windows" in display.lower() and "microsoft" in display.lower()):
            continue

        sig_ok: bool | None = None
        if cmd_path and Path(cmd_path).is_file():
            sig_ok = _ps_signature_ok(cmd_path)

        if sig_ok is False:
            severity = Severity.HIGH
            title = f"Serviço automático sem assinatura: {display or name}"
            rec = "Analise o binário; desative se não for legítimo."
        elif not trusted and not in_pf and sig_ok is not True:
            severity = Severity.MEDIUM
            title = f"Serviço automático de terceiro: {display or name}"
            rec = "Confirme o fabricante e se o serviço precisa iniciar com o Windows."
        else:
            severity = Severity.LOW
            title = f"Serviço automático: {display or name}"
            rec = ""

        result.findings.append(
            Finding(
                check_id="services",
                category="services",
                severity=severity,
                title=title,
                detail=f"{name} ({state}, {start_mode}) → {path}",
                evidence=path or name,
                recommendation=rec,
            )
        )

    return result


# ---------------------------------------------------------------------------
# 3. Tarefas agendadas
# ---------------------------------------------------------------------------


def check_tasks() -> CheckResult:
    result = CheckResult(check_id="tasks", name="Tarefas agendadas")
    out = _run_ps(
        "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | "
        "ForEach-Object { "
        "  $a = $_.Actions | Select-Object -First 1; "
        "  [PSCustomObject]@{ "
        "    TaskName = $_.TaskName; "
        "    TaskPath = $_.TaskPath; "
        "    Execute = $a.Execute; "
        "    Arguments = $a.Arguments; "
        "    Author = $_.Author; "
        "  } "
        "} | ConvertTo-Csv -NoTypeInformation",
        timeout=60.0,
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        result.skipped_reason = "não foi possível enumerar tarefas"
        return result

    rows = list(csv.DictReader(StringIO("\n".join(lines))))
    result.scanned = len(rows)

    for row in rows:
        name = (row.get("TaskName") or "").strip()
        path = (row.get("TaskPath") or "").strip()
        execute = (row.get("Execute") or "").strip()
        args = (row.get("Arguments") or "").strip()
        author = (row.get("Author") or "").strip()

        if not name or not execute:
            continue
        if path.lower().startswith("\\microsoft\\"):
            continue

        cmd_path = _extract_path(execute)
        trusted = _is_trusted_path(cmd_path) if cmd_path else False
        in_pf = _in_program_files(cmd_path)
        sig_ok: bool | None = None
        if cmd_path and Path(cmd_path).is_file():
            sig_ok = _ps_signature_ok(cmd_path)

        if sig_ok is False:
            severity = Severity.HIGH
            title = f"Tarefa agendada sem assinatura: {name}"
            rec = "Revise a tarefa; remova se não reconhecer o autor/binário."
        elif not trusted and not in_pf and sig_ok is not True:
            severity = Severity.MEDIUM
            title = f"Tarefa agendada de terceiro: {name}"
            rec = "Verifique o autor e se a tarefa é esperada."
        else:
            severity = Severity.LOW
            title = f"Tarefa agendada: {name}"
            rec = ""

        result.findings.append(
            Finding(
                check_id="tasks",
                category="tasks",
                severity=severity,
                title=title,
                detail=f"{path}{name} → {execute} {args}".strip(),
                evidence=f"author={author} execute={execute}",
                recommendation=rec,
            )
        )

    return result


# ---------------------------------------------------------------------------
# 4. Listeners de rede
# ---------------------------------------------------------------------------


def check_listeners() -> CheckResult:
    result = CheckResult(check_id="listeners", name="Portas em escuta")
    out = _run_ps(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | "
        "ConvertTo-Csv -NoTypeInformation",
        timeout=30.0,
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        result.skipped_reason = "Get-NetTCPConnection indisponível"
        return result

    rows = list(csv.DictReader(StringIO("\n".join(lines))))
    result.scanned = len(rows)

    pid_map: dict[str, tuple[str, str]] = {}
    ps_out = _run_ps(
        "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Csv -NoTypeInformation",
        timeout=30.0,
    )
    for row in csv.DictReader(
        StringIO("\n".join(ln for ln in ps_out.splitlines() if ln.strip()))
    ):
        pid_map[(row.get("Id") or "").strip()] = (
            (row.get("ProcessName") or "").strip(),
            (row.get("Path") or "").strip(),
        )

    common_ok = {5353, 1900, 5355, 3702, 5357}

    for row in rows:
        port_s = (row.get("LocalPort") or "").strip()
        addr = (row.get("LocalAddress") or "").strip()
        pid = (row.get("OwningProcess") or "").strip()
        try:
            port = int(port_s)
        except ValueError:
            continue

        proc_name, proc_path = pid_map.get(pid, ("?", ""))
        loopback = addr in {"127.0.0.1", "::1", "[::1]"}

        if proc_name.lower() in _COMMON_PROCESSES:
            severity = Severity.INFO
            title = f"Listener comum: {proc_name} :{port}"
            rec = ""
        elif port in common_ok:
            severity = Severity.INFO
            title = f"Listener de descoberta: :{port}"
            rec = ""
        elif not proc_path:
            severity = Severity.LOW
            title = f"Listener :{port} (PID {pid}, processo desconhecido)"
            rec = "Confirme qual aplicação está escutando esta porta."
        elif _is_trusted_path(proc_path):
            severity = Severity.LOW
            title = f"Listener: {proc_name} :{port}"
            rec = ""
        elif loopback:
            severity = Severity.LOW
            title = f"Listener local: {proc_name} :{port}"
            rec = "Escuta só em localhost — normal para apps locais."
        else:
            severity = Severity.MEDIUM
            title = f"Listener de rede: {proc_name} :{port}"
            rec = "Verifique se este programa precisa escutar na rede."

        result.findings.append(
            Finding(
                check_id="listeners",
                category="listeners",
                severity=severity,
                title=title,
                detail=f"{addr}:{port} pid={pid} {proc_name} {proc_path}",
                evidence=proc_path or f"pid={pid}",
                recommendation=rec,
            )
        )

    return result


# ---------------------------------------------------------------------------
# 5. Binários sem assinatura em locais sensíveis
# ---------------------------------------------------------------------------


def check_unsigned_bins() -> CheckResult:
    result = CheckResult(
        check_id="unsigned", name="Binários sem assinatura (locais sensíveis)"
    )

    watch_dirs = [
        Path.home() / "AppData" / "Local" / "Temp",
        Path.home() / "AppData" / "Roaming",
        Path.home() / "Downloads",
        Path(r"C:\Users\Public\Downloads"),
        Path(r"C:\ProgramData"),
    ]

    exts = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
    candidates: list[Path] = []

    for d in watch_dirs:
        if not d.is_dir():
            continue
        try:
            for p in d.rglob("*"):
                if len(candidates) >= 400:
                    break
                if not p.is_file():
                    continue
                if p.suffix.lower() not in exts:
                    continue
                if _is_trusted_path(str(p)):
                    continue
                candidates.append(p)
        except OSError:
            continue

    result.scanned = len(candidates)
    for p in candidates[:200]:
        try:
            st = p.stat()
        except OSError:
            continue
        if st.st_size > 80 * 1024 * 1024:
            continue

        sig_ok = _ps_signature_ok(str(p))
        if sig_ok is False:
            if p.suffix.lower() in {".bat", ".cmd", ".ps1", ".vbs", ".js"}:
                severity = Severity.LOW
                title = f"Script sem assinatura: {p.name}"
            else:
                severity = Severity.MEDIUM
                title = f"Executável sem assinatura: {p.name}"
            result.findings.append(
                Finding(
                    check_id="unsigned",
                    category="unsigned",
                    severity=severity,
                    title=title,
                    detail=str(p),
                    evidence=f"size={st.st_size} status=NotSigned",
                    recommendation=(
                        "Confirme a origem; apague se for resto de instalador/desconhecido."
                    ),
                )
            )

    return result


# ---------------------------------------------------------------------------

Collector = Callable[[], CheckResult]

COLLECTORS: dict[str, tuple[str, Collector]] = {
    "autostart": ("Autostart (Run/Startup/Winlogon)", check_autostart),
    "services": ("Serviços automáticos de terceiros", check_services),
    "tasks": ("Tarefas agendadas ativas", check_tasks),
    "listeners": ("Portas TCP em escuta", check_listeners),
    "unsigned": ("Binários sem assinatura em locais sensíveis", check_unsigned_bins),
}
