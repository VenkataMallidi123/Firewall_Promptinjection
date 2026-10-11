"""Loads firewall/core/config.yaml (optionally merged with a user override file)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

__all__ = ["load_config"]

DEFAULT_CONFIG = Path(__file__).with_name("config.yaml")


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path | None = None, overrides: dict | None = None) -> dict[str, Any]:
    cfg = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    if path:
        cfg = _merge(cfg, yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
    if overrides:
        cfg = _merge(cfg, overrides)
    return cfg
