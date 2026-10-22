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
from clicleaner.disk import analyze_disk
from clicleaner.report import build_report_payload, write_html, write_json
from clicleaner.residue import run_residue_scan
from clicleaner.scan import format_verdict, load_api_key, run_scan

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
        input("Pressione Enter para voltar ao menu…")
    except EOFError:
        pass


def _do_clean_dry() -> None:
    with console.status("Calculando o que pode ser limpo…"):
        report = run_clean(build_targets(), dry_run=True)
    _render_clean_summary(report, applied=False)
    _pause()


def _do_clean_apply() -> None:
    console.print(
        Panel.fit(
            "[bold yellow]ATENÇÃO[/] — esta opção [bold]remove arquivos permanentemente[/].",
            border_style="yellow",
        )
    )
    if console.input("Digite [cyan]SIM[/] para confirmar: ").strip().upper() not in {
        "SIM",
        "S",
        "Y",
        "YES",
    }:
        console.print("[dim]Cancelado.[/]")
        return

    with console.status("Limpando…"):
        report = run_clean(build_targets(), dry_run=False)
    _render_clean_summary(report, applied=True)
    _pause()


def _do_audit(min_severity: Severity, only: set[str] | None = None) -> None:
    label = "rápida" if only else "completa"
    with console.status(f"Rodando auditoria {label}…"):
        report = run_audit(only=only)
    _render_audit(report, min_severity=min_severity, show_all=False)
    _pause()


def _do_doctor() -> None:
    import sys

    admin = is_admin()
    console.print(Panel.fit(f"CLICleaner [bold]{__version__}[/]", title="Ambiente"))
    console.print(f"Python:   [cyan]{sys.version.split()[0]}[/]")
    console.print(
        f"Admin:    [{'green' if admin else 'yellow'}]{'sim' if admin else 'não'}[/]"
    )
    console.print(f"TEMP:     [dim]{__import__('os').environ.get('TEMP', '?')}[/]")
    if not admin:
        console.print(
            "\n[yellow]Sem admin:[/] alvos como Windows Update/Prefetch ficam pulados."
        )
    _pause()


def _do_list_targets() -> None:
    table = Table(title="Alvos de limpeza", show_lines=False)
    table.add_column("id", style="cyan")
    table.add_column("nome")
    table.add_column("admin", justify="center")
    table.add_column("descrição", style="dim")
    for t in build_targets():
        table.add_row(t.id, t.name, "sim" if t.requires_admin else "—", t.description)
    console.print(table)
    _pause()


def _do_list_checks() -> None:
    table = Table(title="Checks de auditoria", show_lines=False)
    table.add_column("id", style="cyan")
    table.add_column("descrição")
    for cid, (label, _fn) in COLLECTORS.items():
        table.add_row(cid, label)
    console.print(table)
    _pause()


def _do_disk() -> None:
    with console.status("Analisando disco…"):
        report = analyze_disk("C:\\", depth=2, top_n=12)

    console.print(
        Panel.fit(
            f"Total: {human_bytes(report.total_bytes)} · "
            f"usado: {human_bytes(report.used_bytes)} · "
            f"livre: [green]{human_bytes(report.free_bytes)}[/]",
            title="Disco C:",
        )
    )
    if report.top_dirs:
        table = Table(title="Maiores pastas", show_lines=False)
        table.add_column("pasta", overflow="fold")
        table.add_column("tamanho", justify="right")
        for d in report.top_dirs:
            table.add_row(d.path, human_bytes(d.size_bytes))
        console.print(table)
    if report.large_files:
        table = Table(title="Arquivos grandes (>200 MB)", show_lines=False)
        table.add_column("arquivo", overflow="fold")
        table.add_column("tamanho", justify="right")
        for f in report.large_files:
            table.add_row(f.path, human_bytes(f.size_bytes))
        console.print(table)
    _pause()


def _do_scan() -> None:
    if not load_api_key():
        console.print(
            "[yellow]Chave do VirusTotal não configurada.[/]\n"
            "1. Crie uma gratuita em [cyan]https://www.virustotal.com/gui/my-apikey[/]\n"
            "2. Rode: [cyan]clicleaner scan --set-key SUA_CHAVE[/]\n"
            "   ou defina [cyan]VT_API_KEY[/] no ambiente."
        )
        _pause()
        return

    with console.status("Consultando VirusTotal…"):
        report = run_scan(max_files=12)

    if report.errors:
        for e in report.errors[:5]:
            console.print(f"[yellow]![/] {e}")

    if not report.results:
        _pause()
        return

    table = Table(title="VirusTotal", show_lines=False)
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
    console.print(
        f"\n[bold red]{len(bad)} suspeito(s)[/] / {len(report.results)} consultados · "
        f"[dim]{report.lookups_used} chamadas à API[/]"
    )
    _pause()


def _do_residue() -> None:
    with console.status("Caçando resíduos…"):
        report = run_residue_scan()

    console.print(
        Panel.fit(
            f"Pastas verificadas: {report.scanned_folders} · "
            f"chaves uninstall: {report.scanned_entries}\n"
            f"Achados: [bold]{len(report.items)}[/] · "
            f"tamanho: [bold]{human_bytes(report.total_bytes)}[/]",
            title="Resíduos",
        )
    )
    if not report.items:
        console.print("[green]Nenhum resíduo óbvio encontrado.[/]")
        _pause()
        return

    table = Table(show_lines=False)
    table.add_column("tipo", style="cyan")
    table.add_column("nome")
    table.add_column("caminho", style="dim", overflow="fold")
    table.add_column("tam.", justify="right")
    table.add_column("ação")
    for item in report.items[:40]:
        action = "[green]ok apagar[/]" if item.safe_to_delete else "[yellow]revisar[/]"
        table.add_row(
            item.kind.value,
            item.name,
            item.path,
            human_bytes(item.size_bytes),
            action,
        )
    console.print(table)
    console.print(
        f"\n[bold]Apagável com mais segurança:[/] {human_bytes(report.deletable_bytes)}"
    )
    _pause()


def _do_report() -> None:
    from datetime import datetime
    from pathlib import Path

    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = Path.cwd()

    with console.status("Gerando relatório…"):
        clean_report = run_clean(build_targets(), dry_run=True)
        audit_report = run_audit(only={"autostart", "services", "listeners"})
        residue_report = run_residue_scan()
        payload = build_report_payload(
            clean=clean_report, audit=audit_report, residue=residue_report
        )
        jpath = write_json(payload, out_dir / f"clicleaner-report_{stamp}.json")
        hpath = write_html(payload, out_dir / f"clicleaner-report_{stamp}.html")

    console.print("[green]Relatório gerado:[/]")
    console.print(f"  [cyan]{jpath}[/]")
    console.print(f"  [cyan]{hpath}[/]")
    _pause()


def _do_exit() -> None:
    console.print("[green]Até logo![/]")
    raise SystemExit(0)


def _render_clean_summary(report, *, applied: bool) -> None:
    table = Table(
        title="Limpeza" + (" (aplicada)" if applied else " (simulação)"),
        show_lines=False,
    )
    table.add_column("alvo", style="cyan")
    table.add_column("itens", justify="right")
    table.add_column("tamanho", justify="right")
    table.add_column("status")
    for r in report.results:
        if r.skipped_reason:
            status = f"[yellow]pulado[/] ({r.skipped_reason})"
        elif applied:
            status = (
                "[green]ok[/]" if not r.errors else f"[red]{len(r.errors)} erro(s)[/]"
            )
        else:
            status = "[dim]dry-run[/]"
        size = r.freed_bytes if applied else r.total_bytes
        table.add_row(r.target.name, str(len(r.items)), human_bytes(size), status)
    console.print(table)

    if applied:
        console.print(
            f"\n[bold green]Removidos[/] {report.total_deleted} itens, "
            f"{human_bytes(report.total_freed_bytes)} liberados."
        )
    else:
        console.print(
            f"\n[bold]Potencial:[/] {human_bytes(report.total_found_bytes)}. "
            "Use a opção [cyan]2[/] para aplicar."
        )


_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _render_audit(report, *, min_severity: Severity, show_all: bool) -> None:
    counts = report.count_by_severity()
    summary = "  ".join(
        f"[{severity_style(s)}]{s.value}={counts[s]}[/]" for s in Severity
    )
    console.print(
        Panel.fit(
            f"Host: [bold]{report.hostname}[/]\nChecks: {len(report.results)}\n{summary}",
            title="Auditoria",
        )
    )

    table = Table(title="Checks", show_lines=False)
    table.add_column("check", style="cyan")
    table.add_column("itens", justify="right")
    table.add_column("achados", justify="right")
    table.add_column("sev. máx")
    table.add_column("status")
    for r in report.results:
        max_sev = r.max_severity
        status = (
            f"[yellow]pulado[/] ({r.skipped_reason})"
            if r.skipped_reason
            else (
                "[green]ok[/]" if not r.errors else f"[red]{len(r.errors)} erro(s)[/]"
            )
        )
        table.add_row(
            r.name,
            str(r.scanned),
            str(len(r.findings)),
            f"[{severity_style(max_sev)}]{max_sev.value}[/]"
            if max_sev
            else "[dim]—[/]",
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
        console.print("\n[dim]Nenhum achado acima do limiar.[/]")
        return

    console.print(f"\n[bold]Achados[/] ({len(findings)}):")
    for f in findings:
        style = severity_style(f.severity)
        console.print(f"  [{style}]■ {f.severity.value}[/{style}] [bold]{f.title}[/]")
        console.print(f"    [dim]{f.detail}[/]")
        if f.recommendation:
            console.print(f"    [italic]{f.recommendation}[/]")

    if not show_all and len(report.all_findings) > len(findings):
        console.print(
            f"\n[dim]… {len(report.all_findings)} no total. "
            "Rode a auditoria completa pelo número [cyan]4[/] ou [cyan]5[/].[/]"
        )


MENU: tuple[MenuEntry, ...] = (
    MenuEntry(
        "1",
        "Limpeza — simular (dry-run)",
        _do_clean_dry,
        "seguro, não apaga nada",
    ),
    MenuEntry("2", "Limpeza — aplicar", _do_clean_apply, "remove arquivos"),
    MenuEntry(
        "3",
        "Auditoria rápida",
        lambda: _do_audit(Severity.LOW, only={"autostart", "services", "listeners"}),
        "sem checagem de assinatura",
    ),
    MenuEntry(
        "4",
        "Auditoria completa",
        lambda: _do_audit(Severity.LOW),
        "inclui unsigned (mais lenta)",
    ),
    MenuEntry(
        "5",
        "Auditoria — só medium+",
        lambda: _do_audit(Severity.MEDIUM),
        "foca no que importa",
    ),
    MenuEntry(
        "6",
        "Caçar resíduos de software",
        _do_residue,
        "pastas/registro/serviços órfãos",
    ),
    MenuEntry("7", "Analisar espaço em disco", _do_disk, "maiores pastas e arquivos"),
    MenuEntry("8", "Scan VirusTotal", _do_scan, "hash de autostart/tarefas"),
    MenuEntry("9", "Gerar relatório (JSON + HTML)", _do_report),
    MenuEntry("10", "Listar alvos de limpeza", _do_list_targets),
    MenuEntry("11", "Listar checks de auditoria", _do_list_checks),
    MenuEntry("12", "Ambiente / privilégios", _do_doctor),
    MenuEntry("0", "Sair", _do_exit),
)


def render_menu() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]CLICleaner[/] v{__version__}\n"
            "[dim]Higiene e auditoria de sistema — auxiliar do Windows Defender[/]",
            border_style="cyan",
        )
    )
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("n", style="bold yellow", justify="right", width=2)
    table.add_column("opção", style="white")
    table.add_column("nota", style="dim")
    for entry in MENU:
        table.add_row(entry.number, entry.label, entry.hint)
    console.print(table)


def run_menu() -> None:
    while True:
        console.print()
        render_menu()
        try:
            choice = console.input("\n[bold cyan]Escolha uma opção:[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[green]Até logo![/]")
            return

        entry = next((e for e in MENU if e.number == choice), None)
        if entry is None:
            console.print(f"[yellow]Opção inválida:[/] {choice!r}. Digite 0–12.")
            continue

        console.print()
        try:
            entry.action()
        except SystemExit:
            raise
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrompido.[/]")
        except Exception as exc:  # noqa: BLE001 — menu não deve derrubar o app
            console.print(f"[red]Erro:[/] {type(exc).__name__}: {exc}")
