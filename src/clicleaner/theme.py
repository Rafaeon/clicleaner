"""Paleta e estilos visuais do CLICleaner."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Paleta — azul/ciano com acentos, contraste bom em fundo escuro.
ACCENT = "bright_cyan"
ACCENT_DIM = "cyan"
BG_CARD = "#161B22"
BORDER = "#30363D"
TEXT = "#E6EDF3"
MUTED = "#8B949E"
OK = "bright_green"
WARN = "bright_yellow"
ERR = "bright_red"
CRIT = "bold bright_red"
INFO = "bright_blue"

BANNER = r"""
  ____ _     ___ ____ _
 / ___| |   |_ _/ ___| | ___  __ _ _ __   ___ _ __
| |   | |    | | |   | |/ _ \/ _` | '_ \ / _ \ '__|
| |___| |___ | | |___| |  __/ (_| | | | |  __/ |
 \____|_____|___\____|_|\___|\__,_|_| |_|\___|_|
"""

TAGLINE = "higiene · auditoria · resíduos · disco · virus total"


def banner_panel(version: str) -> Panel:
    text = Text()
    text.append(BANNER, style=f"bold {ACCENT}")
    text.append(f"  v{version}", style=MUTED)
    text.append(f"  ·  {TAGLINE}\n", style=f"dim {MUTED}")
    return Panel(
        text,
        border_style=ACCENT_DIM,
        padding=(0, 1),
        title=f"[bold {ACCENT}]CLICleaner[/]",
        subtitle=f"[dim {MUTED}]auxiliar do Windows Defender[/]",
    )


def card(
    title: str, body: str, *, border: str = BORDER, title_color: str = ACCENT
) -> Panel:
    return Panel(
        body,
        title=f"[bold {title_color}]{title}[/]",
        border_style=border,
        padding=(1, 2),
    )


def menu_table(entries: list[tuple[str, str, str]]) -> Table:
    table = Table(
        box=None,
        show_header=False,
        padding=(0, 2),
        expand=True,
    )
    table.add_column("", width=3, justify="right", style=f"bold {ACCENT}")
    table.add_column("", min_width=28, style=TEXT, no_wrap=True)
    table.add_column("", style=f"dim {MUTED}", no_wrap=True)
    for num, label, hint in entries:
        table.add_row(f" {num}", label, hint)
    return table


def kv_table(rows: list[tuple[str, str]], *, title: str = "") -> Table:
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        expand=True,
        title=f"[bold {ACCENT}]{title}[/]" if title else None,
    )
    table.add_column("k", style=MUTED, width=28)
    table.add_column("v", style=TEXT)
    for k, v in rows:
        table.add_row(k, v)
    return table


def status_dot(ok: bool | None, yes: str = "ativo", no: str = "inativo") -> str:
    if ok is True:
        return f"[bold {OK}]●[/] {yes}"
    if ok is False:
        return f"[bold {ERR}]●[/] {no}"
    return f"[dim {MUTED}]○[/] ?"


def section(title: str) -> Text:
    t = Text()
    t.append("\n▌ ", style=ACCENT)
    t.append(title, style=f"bold {TEXT}")
    t.append(" ", style=MUTED)
    t.append("─" * max(8, 48 - len(title)), style=BORDER)
    return t
