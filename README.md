# CLICleaner

CLI de **higiene e auditoria de sistema** para Windows — auxiliar do Windows Defender (não substitui antivírus).

## Instalar

```powershell
# com uv
uv tool install .

# ou a partir do GitHub (depois de publicar)
uv tool install git+https://github.com/SEU_USER/clicleaner
```

Depois é só digitar:

```powershell
clicleaner
```

## Menu interativo

```
┌───────────────────────────────────────────────────────────────┐
│ CLICleaner v0.1.0                                             │
│ Higiene e auditoria de sistema — auxiliar do Windows Defender │
└───────────────────────────────────────────────────────────────┘
   1  Limpeza — simular (dry-run)    seguro, não apaga nada
   2  Limpeza — aplicar              remove arquivos
   3  Auditoria rápida               sem checagem de assinatura
   4  Auditoria completa             inclui unsigned (mais lenta)
   5  Auditoria — só medium+         foca no que importa
   6  Listar alvos de limpeza
   7  Listar checks de auditoria
   8  Ambiente / privilégios
   0  Sair
```

## Comandos diretos

```powershell
clicleaner clean               # dry-run (padrão)
clicleaner clean --apply       # aplica limpeza
clicleaner clean --list
clicleaner audit               # auditoria completa
clicleaner audit -o autostart,services
clicleaner audit -m medium
clicleaner doctor
```

## O que ele faz

| Módulo | Função |
|--------|--------|
| **clean** | temp, cache de browser, crash dumps, Windows Update, caches de dev (pip/uv/npm) |
| **audit** | autostart (Run/Startup/Winlogon), serviços, tarefas agendadas, portas em escuta, binários sem assinatura |

### Segurança
- `clean` é **dry-run por padrão** — nada é apagado sem `--apply` / confirmação
- Com filtro de idade, só remove **arquivos antigos** (nunca pastas inteiras)
- Auditoria é **somente leitura**
- Não substitui o Windows Defender

## Desenvolvimento

```powershell
uv sync
uv run ruff check src
uv run pyright src
uv run clicleaner
```

## Requisitos

- Windows 10/11
- Python 3.12 (via [uv](https://docs.astral.sh/uv/))

## Licença

MIT
