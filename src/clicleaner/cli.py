"""CLI do CLICleaner."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from clicleaner import __version__
from clicleaner.audit import run_audit, severity_style, top_findings
from clicleaner.audit.collectors import COLLECTORS
from clicleaner.audit.models import Severity
from clicleaner.clean import build_targets, is_admin, run_clean
from clicleaner.clean.cleaner import human_bytes
from clicleaner.defender import get_defender_status
from clicleaner.disk import analyze_disk
from clicleaner.report import build_report_payload, write_html, write_json
from clicleaner.residue import run_residue_scan
from clicleaner.scan import format_verdict, load_api_key, run_scan, save_api_key

app = typer.Typer(
    name="clicleaner",
    help="CLICleaner — higiene e auditoria de sistema (auxiliar do Windows Defender).",
    add_completion=False,
    no_args_is_help=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"CLICleaner {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Mostra a versão e sai.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """CLICleaner — sem argumentos abre o menu interativo."""
    if ctx.invoked_subcommand is None:
        from clicleaner.menu import run_menu

        run_menu()


@app.command()
def clean(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run/--apply",
            help="Apenas mostra o que seria removido (padrão) ou aplica de verdade.",
        ),
    ] = True,
    only: Annotated[
        list[str] | None,
        typer.Option("--only", "-o", help="Limpa só estes alvos (ids)."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-x", help="Pula estes alvos (ids)."),
    ] = None,
    list_targets: Annotated[
        bool,
        typer.Option("--list", "-l", help="Lista os alvos disponíveis e sai."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Não pede confirmação ao aplicar."),
    ] = False,
) -> None:
    """Limpa caches e temporários comuns (seguro por padrão)."""
    targets = build_targets()

    if list_targets:
        table = Table(title="Alvos de limpeza", show_lines=False)
        table.add_column("id", style="cyan")
        table.add_column("nome")
        table.add_column("admin", justify="center")
        table.add_column("descrição", style="dim")
        for t in targets:
            table.add_row(
                t.id,
                t.name,
                "sim" if t.requires_admin else "—",
                t.description,
            )
        console.print(table)
        return

    only_set = set(only) if only else None
    exclude_set = set(exclude) if exclude else None

    if not dry_run and not yes:
        console.print(
            Panel.fit(
                "[bold yellow]Modo APPLY[/] — arquivos serão "
                "[bold]removidos permanentemente[/].\n"
                "Use [cyan]--dry-run[/] para simular.",
                border_style="yellow",
            )
        )
        if not typer.confirm("Continuar?", default=False):
            raise typer.Exit(code=1)

    report = run_clean(
        targets,
        dry_run=dry_run,
        only=only_set,
        exclude=exclude_set,
    )

    _render_clean_report(report)

    if not dry_run and report.total_deleted:
        console.print(
            f"\n[bold green]Concluído.[/] "
            f"{report.total_deleted} itens removidos, "
            f"{human_bytes(report.total_freed_bytes)} liberados."
        )
    elif dry_run:
        console.print(
            f"\n[bold]Dry-run.[/] Nada foi removido. "
            f"Execute com [cyan]--apply[/] para limpar "
            f"({human_bytes(report.total_found_bytes)} em potencial)."
        )


def _render_clean_report(report) -> None:
    table = Table(
        title=("Simulação de limpeza" if report.dry_run else "Limpeza"),
        show_lines=False,
    )
    table.add_column("alvo", style="cyan")
    table.add_column("itens", justify="right")
    table.add_column("tamanho", justify="right")
    table.add_column("status")

    for r in report.results:
        if r.skipped_reason:
            status = f"[yellow]pulado[/] ({r.skipped_reason})"
        elif r.errors:
            status = f"[red]{len(r.errors)} erro(s)[/]"
        elif report.dry_run:
            status = "[dim]dry-run[/]"
        else:
            status = "[green]ok[/]"

        table.add_row(
            r.target.name,
            str(len(r.items)),
            human_bytes(r.total_bytes if report.dry_run else r.freed_bytes),
            status,
        )

    console.print(table)

    details: list[str] = []
    for r in report.results:
        if r.skipped_reason:
            continue
        for item in r.items[:8]:
            details.append(f"  [dim]{r.target.id}[/] {item.path}")
        if len(r.items) > 8:
            details.append(f"  [dim]{r.target.id}[/] … +{len(r.items) - 8} itens")
        for err in r.errors[:3]:
            details.append(f"  [red]![/] {err}")

    if details:
        console.print("\n[bold]Amostra:[/]")
        console.print("\n".join(details))


@app.command()
def audit(
    only: Annotated[
        list[str] | None,
        typer.Option("--only", "-o", help="Roda só estes checks (ids)."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-x", help="Pula estes checks (ids)."),
    ] = None,
    list_checks: Annotated[
        bool,
        typer.Option("--list", "-l", help="Lista os checks disponíveis e sai."),
    ] = False,
    min_severity: Annotated[
        Severity,
        typer.Option(
            "--min-severity",
            "-m",
            help="Mostra só achados com esta severidade ou acima.",
        ),
    ] = Severity.INFO,
    show_all: Annotated[
        bool,
        typer.Option("--all", "-a", help="Mostra todos os achados, não só o top."),
    ] = False,
) -> None:
    """Audita autostart, serviços, tarefas, listeners e binários sem assinatura."""
    if list_checks:
        table = Table(title="Checks de auditoria", show_lines=False)
        table.add_column("id", style="cyan")
        table.add_column("descrição")
        for cid, (label, _fn) in COLLECTORS.items():
            table.add_row(cid, label)
        console.print(table)
        return

    with console.status("Rodando auditoria…"):
        report = run_audit(
            only=set(only) if only else None,
            exclude=set(exclude) if exclude else None,
        )

    _render_audit_report(report, min_severity=min_severity, show_all=show_all)


def _render_audit_report(report, *, min_severity: Severity, show_all: bool) -> None:
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

    sev_rank = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    threshold = sev_rank[min_severity]
    findings = [
        f
        for f in top_findings(report, limit=10_000 if show_all else 25)
        if sev_rank[f.severity] >= threshold
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
            f"\n[dim]… use [cyan]--all[/] para ver os {len(report.all_findings)} achados.[/]"
        )


@app.command()
def residue(
    only: Annotated[
        list[str] | None,
        typer.Option(
            "--only",
            "-o",
            help="Só estes tipos: folders, uninstall, services, tasks, startup.",
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-x", help="Pula estes tipos."),
    ] = None,
) -> None:
    """Procura resíduos de software (pastas órfãs, registro, serviços quebrados)."""
    with console.status("Caçando resíduos…"):
        report = run_residue_scan(
            only=set(only) if only else None,
            exclude=set(exclude) if exclude else None,
        )
    _render_residue(report)


def _render_residue(report) -> None:
    from clicleaner.residue.models import ResidueKind

    labels = {
        ResidueKind.FOLDER: "Pastas",
        ResidueKind.UNINSTALL_ENTRY: "Registro (uninstall)",
        ResidueKind.SERVICE: "Serviços",
        ResidueKind.TASK: "Tarefas",
        ResidueKind.STARTUP: "Startup",
        ResidueKind.DRIVER: "Drivers",
    }

    console.print(
        Panel.fit(
            f"Host: [bold]{report.hostname}[/]\n"
            f"Pastas verificadas: {report.scanned_folders} · "
            f"Chaves uninstall: {report.scanned_entries}\n"
            f"Achados: [bold]{len(report.items)}[/] · "
            f"tamanho: [bold]{human_bytes(report.total_bytes)}[/]",
            title="Resíduos",
        )
    )

    if report.errors:
        for e in report.errors[:5]:
            console.print(f"  [yellow]![/] {e}")

    if not report.items:
        console.print("[green]Nenhum resíduo óbvio encontrado.[/]")
        return

    table = Table(show_lines=False)
    table.add_column("tipo", style="cyan")
    table.add_column("nome")
    table.add_column("caminho", style="dim", overflow="fold")
    table.add_column("tam.", justify="right")
    table.add_column("ação")

    for item in report.items[:60]:
        action = "[green]ok apagar[/]" if item.safe_to_delete else "[yellow]revisar[/]"
        table.add_row(
            labels.get(item.kind, item.kind.value),
            item.name,
            item.path,
            human_bytes(item.size_bytes),
            action,
        )
    console.print(table)

    # Detalhes
    console.print("\n[bold]Notas:[/]")
    for item in report.items[:20]:
        if item.note:
            console.print(f"  [cyan]{item.name}[/] — {item.note}")

    console.print(
        f"\n[bold]Resumo:[/] {human_bytes(report.deletable_bytes)} em pastas "
        "apagáveis com mais segurança (sempre confira antes)."
    )


@app.command()
def report(
    out: Annotated[
        Path | None,
        typer.Option("--out", "-O", help="Pasta ou arquivo de saída."),
    ] = None,
    formats: Annotated[
        list[str] | None,
        typer.Option("--format", "-f", help="json, html (padrão: ambos)."),
    ] = None,
    skip_audit: Annotated[
        bool,
        typer.Option("--no-audit", help="Não roda auditoria no relatório."),
    ] = False,
    skip_residue: Annotated[
        bool,
        typer.Option("--no-residue", help="Não roda caçada de resíduos."),
    ] = False,
) -> None:
    """Gera relatório consolidado (JSON/HTML) de limpeza + auditoria + resíduos."""
    import platform
    from datetime import datetime

    fmts = {f.lower() for f in formats} if formats else {"json", "html"}
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    base = out or Path.cwd() / "clicleaner-report"
    if base.suffix.lower() in {".json", ".html"}:
        base = base.with_suffix("")

    with console.status("Coletando dados para o relatório…"):
        clean_report = run_clean(build_targets(), dry_run=True)
        audit_report = None if skip_audit else run_audit()
        residue_report = None if skip_residue else run_residue_scan()

    payload = build_report_payload(
        clean=clean_report, audit=audit_report, residue=residue_report
    )

    written: list[Path] = []
    if "json" in fmts:
        written.append(write_json(payload, base.parent / f"{base.name}_{stamp}.json"))
    if "html" in fmts:
        written.append(write_html(payload, base.parent / f"{base.name}_{stamp}.html"))

    console.print(f"[green]Relatório gerado[/] ({platform.node()}):")
    for w in written:
        console.print(f"  [cyan]{w}[/]")


@app.command()
def disk(
    root: Annotated[
        str,
        typer.Option("--root", "-r", help="Unidade/pasta raiz (padrão C:\\)."),
    ] = "C:\\",
    depth: Annotated[
        int,
        typer.Option("--depth", "-d", help="Profundidade de pastas (1–3)."),
    ] = 2,
    top: Annotated[
        int,
        typer.Option("--top", "-n", help="Quantos itens mostrar."),
    ] = 15,
    large_mb: Annotated[
        int,
        typer.Option("--large-mb", help="Tamanho mínimo de arquivo grande."),
    ] = 200,
) -> None:
    """Mostra o que está ocupando espaço no disco."""
    with console.status("Analisando espaço em disco…"):
        report = analyze_disk(
            root, depth=max(1, min(depth, 3)), top_n=top, large_file_mb=large_mb
        )

    console.print(
        Panel.fit(
            f"Raiz: [bold]{report.root}[/]\n"
            f"Total: {human_bytes(report.total_bytes)} · "
            f"usado: {human_bytes(report.used_bytes)} · "
            f"livre: [green]{human_bytes(report.free_bytes)}[/]",
            title="Disco",
        )
    )

    if report.errors:
        for e in report.errors[:5]:
            console.print(f"  [yellow]![/] {e}")

    if report.top_dirs:
        table = Table(title="Maiores pastas", show_lines=False)
        table.add_column("pasta", overflow="fold")
        table.add_column("tamanho", justify="right")
        table.add_column("arquivos", justify="right")
        for d in report.top_dirs:
            table.add_row(d.path, human_bytes(d.size_bytes), str(d.file_count))
        console.print(table)

    if report.large_files:
        table = Table(title=f"Arquivos > {large_mb} MB", show_lines=False)
        table.add_column("arquivo", overflow="fold")
        table.add_column("tamanho", justify="right")
        for f in report.large_files:
            table.add_row(f.path, human_bytes(f.size_bytes))
        console.print(table)


@app.command()
def scan(
    paths: Annotated[
        list[str] | None,
        typer.Argument(
            help="Arquivos ou pastas. Vazio = autostart/tarefas da auditoria."
        ),
    ] = None,
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files", "-n", help="Máximo de consultas (free tier é limitado)."
        ),
    ] = 25,
    set_key: Annotated[
        str | None,
        typer.Option("--set-key", help="Salva a chave da API do VirusTotal e sai."),
    ] = None,
) -> None:
    """Consulta hash de arquivos no VirusTotal (não envia o arquivo)."""
    if set_key:
        path = save_api_key(set_key)
        console.print(f"[green]Chave salva em[/] [cyan]{path}[/]")
        return

    key_hint = "configurada" if load_api_key() else "NÃO configurada"
    console.print(f"[dim]Chave VirusTotal: {key_hint}[/]")

    with console.status("Consultando VirusTotal (pode demorar no free tier)…"):
        report = run_scan(paths, max_files=max_files)

    if not report.api_key_set:
        for e in report.errors:
            console.print(f"[yellow]{e}[/]")
        raise typer.Exit(code=1)

    if report.errors:
        for e in report.errors[:8]:
            console.print(f"  [yellow]![/] {e}")

    if not report.results:
        console.print("[dim]Nada para consultar.[/]")
        return

    table = Table(title="VirusTotal", show_lines=False)
    table.add_column("veredito")
    table.add_column("arquivo", overflow="fold")
    table.add_column("detect.", justify="right")
    table.add_column("sha256", overflow="ellipsis", max_width=16)

    for r in report.results:
        detect = f"{r.malicious}/{r.total_engines}" if r.total_engines else "—"
        table.add_row(
            format_verdict(r.verdict),
            Path(r.path).name if r.path else r.sha256[:12],
            detect,
            r.sha256,
        )
    console.print(table)

    bad = [r for r in report.results if r.verdict.value in {"malicious", "suspicious"}]
    if bad:
        console.print(f"\n[bold red]{len(bad)} arquivo(s) com veredito ruim:[/]")
        for r in bad:
            console.print(f"  [red]■[/] {r.path}")
            if r.permalink:
                console.print(f"    [dim]{r.permalink}[/]")
    else:
        console.print("\n[green]Nenhum veredito malicious/suspicious.[/]")

    console.print(
        f"\n[dim]Consultas usadas: {report.lookups_used} "
        "(free tier: 4/min, 500/dia).[/]"
    )


@app.command()
def doctor() -> None:
    """Verifica privilégios, ambiente e status do Windows Defender."""
    import os
    import sys

    admin = is_admin()
    console.print(Panel.fit(f"CLICleaner [bold]{__version__}[/]", title="Ambiente"))
    console.print(f"Python:   [cyan]{sys.version.split()[0]}[/]")
    console.print(
        f"Admin:    [{'green' if admin else 'yellow'}]{'sim' if admin else 'não'}[/]"
    )
    console.print(f"TEMP:     [dim]{os.environ.get('TEMP', '?')}[/]")

    if not admin:
        console.print(
            "\n[yellow]Sem admin:[/] alvos como Windows Update/Prefetch ficam pulados. "
            "Rode o terminal como administrador para cobrir tudo."
        )

    console.print()
    with console.status("Consultando Windows Defender…"):
        status = get_defender_status()

    if not status.available:
        console.print(
            Panel.fit(
                f"[yellow]{status.error or 'Defender indisponível'}[/]\n"
                "[dim]Comum em ISOs customizadas (Ghost Spectre, AtlasOS…) "
                "ou com outro AV como padrão.[/]",
                title="Windows Defender",
            )
        )
        return

    healthy = status.healthy
    icon = "[green]OK[/]" if healthy else "[red]atenção[/]"
    body = "\n".join(
        [
            f"Proteção em tempo real:     {status.real_time and '[green]sim[/]' or '[red]não[/]'}",
            f"Antivírus ativo:            {status.antivirus_enabled and '[green]sim[/]' or '[red]não[/]'}",
            f"Anti-spyware:               {status.antispyware_enabled and '[green]sim[/]' or '[red]não[/]'}",
            f"Monitor de comportamento:   {status.behavior_monitor and '[green]sim[/]' or '[yellow]não[/]'}",
            f"Anti-adulteração:           {status.tamper_protection and '[green]sim[/]' or '[yellow]não[/]'}",
            f"Proteção em nuvem:          {status.cloud_protection and '[green]sim[/]' or '[yellow]não[/]'}",
            f"Assinaturas:                {status.signature_age_days} dia(s) · {status.signature_version or '—'}",
            f"Último scan rápido:         {status.quick_scan_end or '—'}",
            f"Último scan completo:       {status.full_scan_end or '—'}",
        ]
    )
    console.print(Panel.fit(body, title=f"Windows Defender — {icon}"))

    if status.signature_age_days is not None and status.signature_age_days > 3:
        console.print(
            "[yellow]Assinaturas desatualizadas.[/] Rode "
            "[cyan]Update-MpSignature[/] no PowerShell (admin)."
        )


if __name__ == "__main__":
    app()
