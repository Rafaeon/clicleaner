"""Configuração do CLICleaner (chave da API VirusTotal)."""

from __future__ import annotations

import json
import os
from pathlib import Path

_CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "clicleaner"
_CONFIG_PATH = _CONFIG_DIR / "config.json"


def config_path() -> Path:
    return _CONFIG_PATH


def load_api_key() -> str | None:
    """Lê a chave de VT_API_KEY ou do config file (nunca grava no repositório)."""
    env = os.environ.get("VT_API_KEY", "").strip()
    if env:
        return env
    try:
        data = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        key = (data.get("vt_api_key") or "").strip()
        return key or None
    except (OSError, json.JSONDecodeError):
        return None


def save_api_key(key: str) -> Path:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data: dict[str, str] = {}
    if _CONFIG_PATH.exists():
        try:
            data = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
    data["vt_api_key"] = key.strip()
    _CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return _CONFIG_PATH
