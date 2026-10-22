"""Menu interativo do CLICleaner (seleção por número)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clicleaner import __version__
from clicleaner.audit.auditor import run_audit, severity_style, top_findings
from clicleaner.audit.collectors import COLLECTORS
from clicleaner.audit.models import Severity
from clicleaner.clean import build_targets, is_admin, run_clean
from clicleaner.clean.cleaner import human_bytes
from clicleaner.defender import get_defender_status
from clicleaner.disk import analyze_disk
from clicleaner.report import build_report_payload, write_html, write_json
from clicleaner.residue import run_residue_scan
from clicleaner.scan import format_verdict, load_api_key, run_scan
from clicleaner.theme import (
    ACCENT,
    ACCENT_DIM,
    ERR,
    INFO,
    MUTED,
    OK,
    TEXT,
    WARN,
    banner_panel,
    card,
    kv_table,
    menu_table,
    section,
    status_dot,
)

console = Console()


@dataclass(frozen=True, slots=True)
class MenuEntry:
    number: str
    label: str
    action: Callable[[], None]
    hint: str = ""


def _pause() -> None:
    try:
        console.print()
        console.input(
            f"[dim {MUTED}]Enter para voltar ao menu[/] "
            f"[dim {ACCENT_DIM}]/[/] [dim {MUTED}]0 para sair[/] "
        )
    except EOFError:
        pass


def _do_clean_dry() -> None:
    console.print(section("Limpeza — simulação"))
    with console.status(f"[{ACCENT_DIM}]calculando…[/]"):
        report = run_clean(build_targets(), dry_run=True)
    _render_clean_summary(report, applied=False)
    _pause()


def _do_clean_apply() -> None:
    console.print(section("Limpeza — aplicar"))
    console.print(
        Panel.fit(
            f"[bold {ERR}]ATENÇÃO[/]  arquivos serão "
            f"[bold {TEXT}]removidos permanentemente[/].",
            border_style=ERR,
            padding=(0, 2),
        )
    )
    answer = console.input(f"Digite [{ACCENT}]SIM[/] para confirmar: ").strip().upper()
    if answer not in {"SIM", "S", "Y", "YES"}:
        console.print(f"[dim {MUTED}]Cancelado.[/]")
        return

    with console.status(f"[{ACCENT_DIM}]limpando…[/]"):
        report = run_clean(build_targets(), dry_run=False)
    _render_clean_summary(report, applied=True)
    _pause()


def _do_audit(min_severity: Severity, only: set[str] | None = None) -> None:
    label = "rápida" if only else "completa"
    console.print(section(f"Auditoria {label}"))
    with console.status(f"[{ACCENT_DIM}]varrendo sistema…[/]"):
        report = run_audit(only=only)
    _render_audit(report, min_severity=min_severity, show_all=False)
    _pause()


def _do_doctor() -> None:
    import sys

    admin = is_admin()
    console.print(section("Ambiente"))
    console.print(
        kv_table(
            [
                ("versão", __version__),
                ("python", sys.version.split()[0]),
                ("admin", status_dot(admin, "sim", "não")),
                ("temp", __import__("os").environ.get("TEMP", "—")),
            ]
        )
    )

    with console.status(f"[{ACCENT_DIM}]consultando Windows Defender…[/]"):
        st = get_defender_status()

    if not st.available:
        console.print(
            card(
                "Windows Defender",
                f"[{WARN}]{st.error or 'indisponível'}[/]\n"
                f"[dim {MUTED}]comum em ISOs customizadas "
                "(Ghost Spectre, AtlasOS…)[/]",
                border=WARN,
            )
        )
    else:
        rows = [
            ("tempo real", status_dot(st.real_time)),
            ("antivírus", status_dot(st.antivirus_enabled)),
            ("anti-spyware", status_dot(st.antispyware_enabled)),
            ("comportamento", status_dot(st.behavior_monitor)),
            ("anti-adulteração", status_dot(st.tamper_protection)),
            ("nuvem", status_dot(st.cloud_protection)),
            (
                "assinaturas",
                f"{st.signature_age_days or '?'} dia(s) · {st.signature_version or '—'}",
            ),
            ("scan rápido", st.quick_scan_end or "—"),
            ("scan completo", st.full_scan_end or "—"),
        ]
        flag = OK if st.healthy else ERR
        console.print(
            Panel(
                kv_table(rows),
                title=f"[bold {flag}]Windows Defender[/]",
                border_style=flag,
                padding=(0, 1),
            )
        )

    if not admin:
        console.print(
            f"\n[{WARN}]sem admin:[/] alvos como Windows Update/Prefetch ficam pulados."
        )
    _pause()


def _do_list_targets() -> None:
    console.print(section("Alvos de limpeza"))
    table = Table(show_header=True, header_style=f"bold {ACCENT}", expand=True)
    for col in ("id", "nome", "admin", "descrição"):
        table.add_column(col, style=TEXT if col != "id" else ACCENT_DIM)
    for t in build_targets():
        admin = f"[{WARN}]sim[/]" if t.requires_admin else f"[dim {MUTED}]—[/]"
        table.add_row(t.id, t.name, admin, t.description)
    console.print(table)
    _pause()


def _do_list_checks() -> None:
    console.print(section("Checks de auditoria"))
    table = Table(show_header=True, header_style=f"bold {ACCENT}", expand=True)
    table.add_column("id", style=ACCENT_DIM)
    table.add_column("descrição", style=TEXT)
    for cid, (label, _fn) in COLLECTORS.items():
        table.add_row(cid, label)
    console.print(table)
    _pause()


def _do_residue() -> None:
    console.print(section("Caçador de resíduos"))
    with console.status(f"[{ACCENT_DIM}]procurando sobras…[/]"):
        report = run_residue_scan()

    console.print(
        kv_table(
            [
                ("pastas verificadas", str(report.scanned_folders)),
                ("chaves uninstall", str(report.scanned_entries)),
                ("achados", f"[bold]{len(report.items)}[/]"),
                ("tamanho", f"[bold]{human_bytes(report.total_bytes)}[/]"),
            ]
        )
    )

    if not report.items:
        console.print(f"\n[{OK}]nada óbvio por aqui.[/]")
        _pause()
        return

    table = Table(
        show_header=True,
        header_style=f"bold {ACCENT}",
        expand=True,
        border_style="#30363D",
    )
    for col in ("tipo", "nome", "caminho", "tam.", "ação"):
        table.add_column(col, overflow="fold" if col == "caminho" else "ellipsis")

    for item in report.items[:40]:
        action = f"[{OK}]ok[/]" if item.safe_to_delete else f"[{WARN}]revisar[/]"
        table.add_row(
            item.kind.value,
            item.name,
            item.path,
            human_bytes(item.size_bytes),
            action,
        )
    console.print(table)
    console.print(
        f"\n[{OK}]apagável com mais segurança:[/] "
        f"{human_bytes(report.deletable_bytes)} "
        f"[dim {MUTED}]— confira sempre antes[/]"
    )
    _pause()


def _do_disk() -> None:
    console.print(section("Espaço em disco"))
    with console.status(f"[{ACCENT_DIM}]analisando C:\\…[/]"):
        report = analyze_disk("C:\\", depth=2, top_n=12)

    free_pct = 100 * report.free_bytes / report.total_bytes if report.total_bytes else 0
    console.print(
        kv_table(
            [
                (
                    "partição",
                    (
                        f"{human_bytes(report.total_bytes)} · "
                        f"usado {human_bytes(report.used_bytes)} · "
                        f"livre [{OK}]{human_bytes(report.free_bytes)}[/] ({free_pct:.0f}%)"
                    ),
                ),
            ]
        )
    )

    if report.top_dirs:
        table = Table(
            title=f"[bold {ACCENT}]maiores pastas[/]",
            show_header=True,
            header_style=MUTED,
            expand=True,
        )
        table.add_column("pasta", overflow="fold", style=TEXT)
        table.add_column("tamanho", justify="right", style=ACCENT)
        table.add_column("arquivos", justify="right", style=MUTED)
        for d in report.top_dirs:
            table.add_row(d.path, human_bytes(d.size_bytes), str(d.file_count))
        console.print(table)

    if report.large_files:
        table = Table(
            title=f"[bold {ACCENT}]arquivos grandes[/]",
            show_header=True,
            header_style=MUTED,
            expand=True,
        )
        table.add_column("arquivo", overflow="fold", style=TEXT)
        table.add_column("tamanho", justify="right", style=WARN)
        for f in report.large_files:
            table.add_row(f.path, human_bytes(f.size_bytes))
        console.print(table)
    _pause()


def _do_scan() -> None:
    console.print(section("Scan VirusTotal"))
    if not load_api_key():
        console.print(
            Panel.fit(
                f"[{WARN}]chave não configurada[/]\n\n"
                f"  1. crie em [underline {ACCENT}]https://www.virustotal.com/gui/my-apikey[/]\n"
                f"  2. rode [{ACCENT}]clicleaner scan --set-key SUA_CHAVE[/]\n"
                f"  3. ou defina [{ACCENT}]VT_API_KEY[/]",
                border_style=WARN,
                padding=(1, 2),
            )
        )
        _pause()
        return

    with console.status(f"[{ACCENT_DIM}]consultando VirusTotal…[/]"):
        report = run_scan(max_files=12)

    if report.errors:
        for e in report.errors[:5]:
            console.print(f"[{WARN}]![/] {e}")

    if not report.results:
        _pause()
        return

    table = Table(show_header=True, header_style=f"bold {ACCENT}", expand=True)
    table.add_column("veredito")
    table.add_column("arquivo", overflow="fold")
    table.add_column("detect.", justify="right")
    for r in report.results:
        detect = f"{r.malicious}/{r.total_engines}" if r.total_engines else "—"
        table.add_row(
            format_verdict(r.verdict),
            Path(r.path).name if r.path else r.sha256[:12],
            detect,
        )
    console.print(table)

    bad = [r for r in report.results if r.verdict.value in {"malicious", "suspicious"}]
    if bad:
        console.print(f"\n[bold {ERR}]{len(bad)} com veredito ruim[/]")
        for r in bad:
            console.print(f"  [{ERR}]■[/] {r.path}")
            if r.permalink:
                console.print(f"    [dim {MUTED}]{r.permalink}[/]")
    else:
        console.print(f"\n[{OK}]nenhum malicious/suspicious.[/]")
    console.print(f"[dim {MUTED}]{report.lookups_used} consultas (free tier ~4/min)[/]")
    _pause()


def _do_report() -> None:
    from datetime import datetime

    console.print(section("Relatório"))
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = Path.cwd()

    with console.status(f"[{ACCENT_DIM}]coletando dados…[/]"):
        clean_report = run_clean(build_targets(), dry_run=True)
        audit_report = run_audit(only={"autostart", "services", "listeners"})
        residue_report = run_residue_scan()
        payload = build_report_payload(
            clean=clean_report, audit=audit_report, residue=residue_report
        )
        jpath = write_json(payload, out_dir / f"clicleaner-report_{stamp}.json")
        hpath = write_html(payload, out_dir / f"clicleaner-report_{stamp}.html")

    console.print(f"[{OK}]gerado[/]")
    console.print(f"  [{ACCENT}]json[/]  {jpath}")
    console.print(f"  [{ACCENT}]html[/]  {hpath}")
    _pause()


def _do_exit() -> None:
    console.print(f"[{OK}]até logo![/]")
    raise SystemExit(0)


_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _render_clean_summary(report, *, applied: bool) -> None:
    table = Table(show_header=True, header_style=f"bold {ACCENT}", expand=True)
    for col in ("alvo", "itens", "tamanho", "status"):
        table.add_column(
            col, justify="right" if col in {"itens", "tamanho"} else "left"
        )

    for r in report.results:
        if r.skipped_reason:
            status = f"[{MUTED}]pulado[/]"
        elif applied:
            status = (
                f"[{OK}]ok[/]" if not r.errors else f"[{ERR}]{len(r.errors)} erro[/]"
            )
        else:
            status = f"[{INFO}]dry-run[/]"
        size = r.freed_bytes if applied else r.total_bytes
        table.add_row(r.target.name, str(len(r.items)), human_bytes(size), status)
    console.print(table)

    if applied:
        console.print(
            f"\n[{OK}]removidos[/] {report.total_deleted} itens · "
            f"[bold]{human_bytes(report.total_freed_bytes)}[/] liberados."
        )
    else:
        console.print(
            f"\n[{INFO}]potencial[/] [bold]{human_bytes(report.total_found_bytes)}[/] · "
            f"opção [{ACCENT}]2[/] aplica."
        )


def _render_audit(report, *, min_severity: Severity, show_all: bool) -> None:
    counts = report.count_by_severity()
    parts = []
    for s in Severity:
        n = counts[s]
        if n:
            parts.append(f"[{severity_style(s)}]{s.value}={n}[/]")
    console.print(
        kv_table(
            [
                ("host", report.hostname),
                ("checks", str(len(report.results))),
                ("achados", "  ".join(parts) or f"[dim {MUTED}]nenhum[/]"),
            ]
        )
    )

    table = Table(show_header=True, header_style=f"bold {ACCENT}", expand=True)
    for col in ("check", "itens", "achados", "sev", "status"):
        table.add_column(
            col, justify="right" if col in {"itens", "achados"} else "left"
        )

    for r in report.results:
        max_sev = r.max_severity
        status = (
            f"[{MUTED}]pulado[/]"
            if r.skipped_reason
            else (f"[{OK}]ok[/]" if not r.errors else f"[{ERR}]{len(r.errors)} erro[/]")
        )
        table.add_row(
            r.name,
            str(r.scanned),
            str(len(r.findings)),
            f"[{severity_style(max_sev)}]{max_sev.value}[/]"
            if max_sev
            else f"[dim {MUTED}]—[/]",
            status,
        )
    console.print(table)

    threshold = _SEV_RANK[min_severity]
    findings = [
        f
        for f in top_findings(report, limit=10_000 if show_all else 25)
        if _SEV_RANK[f.severity] >= threshold
    ]

    if not findings:
        console.print(f"\n[{OK}]nenhum achado acima do limiar.[/]")
        return

    console.print(section(f"Achados ({len(findings)})"))
    for f in findings:
        style = severity_style(f.severity)
        console.print(
            f"  [{style}]■[/] [{style}]{f.severity.value}[/]  [bold]{f.title}[/]"
        )
        console.print(f"      [dim {MUTED}]{f.detail}[/]")
        if f.recommendation:
            console.print(f"      [italic {MUTED}]{f.recommendation}[/]")

    if not show_all and len(report.all_findings) > len(findings):
        console.print(
            f"\n[dim {MUTED}]{len(report.all_findings)} no total · "
            f"opções 4/5 mostram mais[/]"
        )


MENU: tuple[MenuEntry, ...] = (
    MenuEntry("1", "Limpeza — simular", _do_clean_dry, "dry-run"),
    MenuEntry("2", "Limpeza — aplicar", _do_clean_apply, "remove arquivos"),
    MenuEntry(
        "3",
        "Auditoria rápida",
        lambda: _do_audit(Severity.LOW, only={"autostart", "services", "listeners"}),
        "sem assinatura",
    ),
    MenuEntry(
        "4", "Auditoria completa", lambda: _do_audit(Severity.LOW), "com assinatura"
    ),
    MenuEntry(
        "5", "Auditoria medium+", lambda: _do_audit(Severity.MEDIUM), "só o crítico"
    ),
    MenuEntry("6", "Resíduos de software", _do_residue, "órfãos no sistema"),
    MenuEntry("7", "Espaço em disco", _do_disk, "top pastas/arquivos"),
    MenuEntry("8", "Scan VirusTotal", _do_scan, "hash + reputação"),
    MenuEntry("9", "Relatório JSON + HTML", _do_report, "exporta snapshot"),
    MenuEntry("10", "Alvos de limpeza", _do_list_targets, "lista do clean"),
    MenuEntry("11", "Checks de auditoria", _do_list_checks, "lista do audit"),
    MenuEntry("12", "Ambiente + Defender", _do_doctor, "status do sistema"),
    MenuEntry("0", "Sair", _do_exit, ""),
)


def render_menu() -> None:
    console.print(banner_panel(__version__))
    console.print(menu_table([(e.number, e.label, e.hint) for e in MENU]))
    console.print()


def run_menu() -> None:
    while True:
        render_menu()
        try:
            choice = console.input(f"  [bold {ACCENT}]▸[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print(f"\n[{OK}]até logo![/]")
            return

        entry = next((e for e in MENU if e.number == choice), None)
        if entry is None:
            console.print(f"[{WARN}]opção inválida:[/] {choice!r}  [dim]use 0–12[/]")
            continue

        console.print()
        try:
            entry.action()
        except SystemExit:
            raise
        except KeyboardInterrupt:
            console.print(f"\n[{WARN}]interrompido.[/]")
        except Exception as exc:  # noqa: BLE001 — menu não deve derrubar o app
            console.print(f"[{ERR}]erro:[/] {type(exc).__name__}: {exc}")
