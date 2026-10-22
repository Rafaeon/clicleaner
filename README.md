# CLICleaner

Limpeza e auditoria de sistema para Windows, direto no terminal.  
Auxiliar do Windows Defender — **não** substitui um antivírus.

## Instalar

```powershell
uv tool install git+https://github.com/Rafaeon/clicleaner
```

Ou clonar e instalar:

```powershell
git clone https://github.com/Rafaeon/clicleaner
cd clicleaner
uv tool install .
```

Depois é só rodar:

```powershell
clicleaner
```

## Menu

```
 1  Limpeza — simular (dry-run)    seguro, não apaga nada
 2  Limpeza — aplicar              remove arquivos
 3  Auditoria rápida               autostart, serviços, portas
 4  Auditoria completa             inclui checagem de assinatura
 5  Auditoria — só medium+         foca no que importa
 6  Listar alvos de limpeza
 7  Listar checks de auditoria
 8  Ambiente / privilégios
 0  Sair
```

## Comandos

```powershell
clicleaner clean               # mostra o que seria limpo (não apaga)
clicleaner clean --apply       # limpa de verdade
clicleaner audit               # auditoria completa
clicleaner audit -m medium     # só achados medium+
clicleaner doctor
```

## O que faz

**Limpeza** — temp, cache de navegador, crash dumps, Windows Update, caches de dev (pip/uv/npm).

**Auditoria** — entradas de autostart, serviços automáticos, tarefas agendadas, portas em escuta e executáveis sem assinatura.

## Segurança

- Limpeza é **dry-run por padrão** — nada é apagado sem confirmação
- Com filtro de idade, só remove arquivos antigos (nunca pastas inteiras)
- Auditoria é somente leitura

## Requisitos

Windows 10/11 · Python 3.12 · [uv](https://docs.astral.sh/uv/)

## Licença

MIT
