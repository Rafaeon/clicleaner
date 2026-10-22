"""Cliente mínimo da API v3 do VirusTotal (só lookup por hash)."""

from __future__ import annotations

import time
from typing import Any

from clicleaner.scan.models import FileScanResult, VTVerdict

_BASE = "https://www.virustotal.com/api/v3"
# Free tier: 4 requisições/min — deixamos folga.
_MIN_INTERVAL_SEC = 16.0


class VTClient:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._last_call = 0.0

    def _throttle(self) -> None:
        wait = _MIN_INTERVAL_SEC - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def _get(self, url: str) -> dict[str, Any] | None:
        import urllib.error
        import urllib.request

        self._throttle()
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": self._api_key,
                "Accept": "application/json",
                "User-Agent": "CLICleaner/0.1",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                import json

                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code == 401:
                raise PermissionError("chave da API VirusTotal inválida") from exc
            if exc.code == 429:
                raise RuntimeError(
                    "rate limit do VirusTotal — aguarde um minuto"
                ) from exc
            raise RuntimeError(f"HTTP {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"falha de rede: {exc.reason}") from exc

    def lookup_hash(self, sha256: str) -> FileScanResult | None:
        """Consulta um hash. Retorna None se nunca foi analisado."""
        data = self._get(f"{_BASE}/files/{sha256}")
        if not data:
            return None
        attrs = data.get("attributes") or {}
        stats = (attrs.get("last_analysis_stats") or {}) or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            verdict = VTVerdict.MALICIOUS
        elif suspicious >= max(2, malicious + 1) or (
            suspicious > 0 and total > 0 and suspicious / max(total, 1) > 0.1
        ):
            verdict = VTVerdict.SUSPICIOUS
        elif harmless + undetected > 0:
            verdict = VTVerdict.HARMLESS
        else:
            verdict = VTVerdict.UNKNOWN

        link = f"https://www.virustotal.com/gui/file/{sha256}"
        return FileScanResult(
            path="",
            sha256=sha256,
            size_bytes=int(attrs.get("size") or 0),
            verdict=verdict,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            total_engines=total,
            permalink=link,
        )
