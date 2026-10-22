"""Export de relatórios em JSON e HTML."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clicleaner import __version__
from clicleaner.audit.models import AuditReport
from clicleaner.clean.cleaner import CleanReport, human_bytes
from clicleaner.residue.models import ResidueReport


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def clean_to_dict(report: CleanReport) -> dict[str, Any]:
    return {
        "module": "clean",
        "dry_run": report.dry_run,
        "started_at": _iso(report.started_at),
        "finished_at": _iso(report.finished_at),
        "total_found_bytes": report.total_found_bytes,
        "total_freed_bytes": report.total_freed_bytes,
        "total_deleted": report.total_deleted,
        "targets": [
            {
                "id": r.target.id,
                "name": r.target.name,
                "items": len(r.items),
                "bytes": r.total_bytes,
                "deleted": r.deleted,
                "freed_bytes": r.freed_bytes,
                "skipped": r.skipped_reason,
                "errors": r.errors,
                "paths": [str(i.path) for i in r.items[:50]],
            }
            for r in report.results
        ],
    }


def audit_to_dict(report: AuditReport) -> dict[str, Any]:
    return {
        "module": "audit",
        "hostname": report.hostname,
        "started_at": _iso(report.started_at),
        "finished_at": _iso(report.finished_at),
        "counts": {s.value: n for s, n in report.count_by_severity().items()},
        "checks": [
            {
                "id": r.check_id,
                "name": r.name,
                "scanned": r.scanned,
                "skipped": r.skipped_reason,
                "errors": r.errors,
                "findings": [
                    {
                        "severity": f.severity.value,
                        "title": f.title,
                        "detail": f.detail,
                        "evidence": f.evidence,
                        "recommendation": f.recommendation,
                        "category": f.category,
                    }
                    for f in r.findings
                ],
            }
            for r in report.results
        ],
    }


def residue_to_dict(report: ResidueReport) -> dict[str, Any]:
    return {
        "module": "residue",
        "hostname": report.hostname,
        "started_at": _iso(report.started_at),
        "finished_at": _iso(report.finished_at),
        "scanned_folders": report.scanned_folders,
        "scanned_entries": report.scanned_entries,
        "total_bytes": report.total_bytes,
        "deletable_bytes": report.deletable_bytes,
        "errors": report.errors,
        "items": [
            {
                "kind": i.kind.value,
                "name": i.name,
                "path": i.path,
                "detail": i.detail,
                "size_bytes": i.size_bytes,
                "safe_to_delete": i.safe_to_delete,
                "note": i.note,
            }
            for i in report.items
        ],
    }


def build_report_payload(
    *,
    clean: CleanReport | None = None,
    audit: AuditReport | None = None,
    residue: ResidueReport | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "app": "CLICleaner",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "modules": {},
    }
    if clean is not None:
        payload["modules"]["clean"] = clean_to_dict(clean)
    if audit is not None:
        payload["modules"]["audit"] = audit_to_dict(audit)
    if residue is not None:
        payload["modules"]["residue"] = residue_to_dict(residue)
    return payload


def write_json(payload: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


_CSS = """
body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e7ecf1; }
h1 { color: #4cc2ff; margin-bottom: .25rem; }
h2 { color: #7ee2ff; border-bottom: 1px solid #2a3540; padding-bottom: .35rem; }
.meta { color: #8b9bab; margin-bottom: 1.5rem; }
.card { background: #1a222c; border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }
table { width: 100%; border-collapse: collapse; font-size: .92rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #2a3540; vertical-align: top; }
th { color: #8b9bab; font-weight: 600; }
.sev-info { color: #8b9bab; } .sev-low { color: #6bcb77; } .sev-medium { color: #ffd166; }
.sev-high { color: #ff6b6b; } .sev-critical { color: #ff3b3b; font-weight: 700; }
.badge { display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .8rem; background: #24303c; }
.ok { background: #1b3d2f; color: #6bcb77; } .warn { background: #3d3420; color: #ffd166; }
.muted { color: #8b9bab; font-size: .85rem; }
ul { margin: .35rem 0 .35rem 1.1rem; }
"""


def write_html(payload: dict[str, Any], path: Path) -> Path:
    parts: list[str] = []
    parts.append("<!DOCTYPE html><html lang='pt-BR'><head><meta charset='utf-8'>")
    parts.append(
        f"<title>CLICleaner — relatório</title><style>{_CSS}</style></head><body>"
    )
    parts.append(
        f"<h1>CLICleaner</h1><div class='meta'>v{payload.get('version', '?')} · "
        f"gerado em {payload.get('generated_at', '')}</div>"
    )

    modules = payload.get("modules", {})

    if "clean" in modules:
        c = modules["clean"]
        parts.append("<h2>Limpeza</h2><div class='card'>")
        parts.append(
            f"<p>Modo: <span class='badge'>{'dry-run' if c.get('dry_run') else 'aplicado'}</span> · "
            f"potencial <strong>{human_bytes(c.get('total_found_bytes', 0))}</strong> · "
            f"liberado <strong>{human_bytes(c.get('total_freed_bytes', 0))}</strong></p>"
        )
        parts.append(
            "<table><tr><th>alvo</th><th>itens</th><th>tamanho</th><th>status</th></tr>"
        )
        for t in c.get("targets", []):
            status = t.get("skipped") or (
                "ok" if not t.get("errors") else f"{len(t['errors'])} erro(s)"
            )
            cls = "warn" if t.get("skipped") else "ok"
            parts.append(
                f"<tr><td>{t['name']}</td><td>{t['items']}</td>"
                f"<td>{human_bytes(t.get('bytes', 0))}</td>"
                f"<td><span class='badge {cls}'>{status}</span></td></tr>"
            )
        parts.append("</table></div>")

    if "audit" in modules:
        a = modules["audit"]
        parts.append("<h2>Auditoria</h2><div class='card'>")
        counts = a.get("counts", {})
        badges = " ".join(
            f"<span class='badge sev-{k}'>{k}={v}</span>"
            for k, v in counts.items()
            if v
        )
        parts.append(
            f"<p>Host <strong>{a.get('hostname', '')}</strong> · {badges or '<span class=muted>sem achados</span>'}</p>"
        )

        findings = []
        for check in a.get("checks", []):
            for f in check.get("findings", []):
                findings.append((check.get("name", ""), f))
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: order.get(x[1].get("severity", "info"), 9))

        if findings:
            parts.append(
                "<table><tr><th>sev</th><th>check</th><th>achado</th><th>detalhe</th></tr>"
            )
            for check_name, f in findings[:80]:
                sev = f.get("severity", "info")
                parts.append(
                    f"<tr><td class='sev-{sev}'>{sev}</td><td>{check_name}</td>"
                    f"<td><strong>{f.get('title', '')}</strong>"
                    f"<div class='muted'>{f.get('recommendation', '')}</div></td>"
                    f"<td class='muted'>{f.get('detail', '')}</td></tr>"
                )
            parts.append("</table>")
        parts.append("</div>")

    if "residue" in modules:
        r = modules["residue"]
        parts.append("<h2>Resíduos</h2><div class='card'>")
        parts.append(
            f"<p>{len(r.get('items', []))} item(ns) · "
            f"<strong>{human_bytes(r.get('total_bytes', 0))}</strong> · "
            f"apagável com segurança: <strong>{human_bytes(r.get('deletable_bytes', 0))}</strong></p>"
        )
        items = r.get("items", [])
        if items:
            parts.append(
                "<table><tr><th>tipo</th><th>nome</th><th>caminho</th>"
                "<th>tamanho</th><th>nota</th></tr>"
            )
            for i in items[:80]:
                safe = i.get("safe_to_delete")
                badge = (
                    "<span class='badge ok'>ok</span>"
                    if safe
                    else "<span class='badge warn'>revisar</span>"
                )
                parts.append(
                    f"<tr><td>{i.get('kind', '')}</td><td>{i.get('name', '')}</td>"
                    f"<td class='muted'>{i.get('path', '')}</td>"
                    f"<td>{human_bytes(i.get('size_bytes', 0))}</td>"
                    f"<td>{badge} {i.get('note', '')}</td></tr>"
                )
            parts.append("</table>")
        parts.append("</div>")

    parts.append("</body></html>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(parts), encoding="utf-8")
    return path
