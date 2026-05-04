from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_cached: dict | None = None


def load_config() -> dict:
    global _cached
    if _cached is not None:
        return _cached
    for name in ("sqlshield.yaml", "sqlshield.yml"):
        if os.path.exists(name):
            try:
                import yaml
                with open(name) as f:
                    _cached = yaml.safe_load(f) or {}
                    return _cached
            except Exception as exc:
                logger.warning("could not parse %s: %s", name, exc)
    _cached = {}
    return _cached


def _env_or(env_key: str, yaml_value, default):
    raw = os.environ.get(env_key)
    if raw is not None:
        return raw
    if yaml_value is not None:
        return yaml_value
    return default
