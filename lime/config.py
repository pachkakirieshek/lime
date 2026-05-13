"""
Конфиг lime из ~/.config/lime/config.toml

Используем только stdlib — tomllib (Python 3.11+) или ручной парсер для
совместимости с 3.10. Если файла нет — используются дефолты.
"""

import os
import sys
from pathlib import Path

_CONFIG_PATH = Path.home() / ".config" / "lime" / "config.toml"

# ── Дефолтные значения ─────────────────────────────────────────────────────
DEFAULTS: dict = {
    "general": {
        "lang":  os.environ.get("LIME_LANG", "ru"),
        "color": True,
    },
    "risk": {
        # При каком уровне прерывать без подтверждения (None = никогда)
        "abort_level": "Keter",
        # При каком уровне спрашивать подтверждение
        "confirm_level": "High",
    },
    "whitelist": {
        # Дополнительные пакеты пользователя (добавляются к встроенному WHITELIST)
        "extra": [],
    },
    "plugins": {
        # Имена классов плагинов которые нужно отключить
        "disabled": [],
    },
    "cache": {
        "dir": "/tmp/lime-cache",
        "max_age_days": 7,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивно мёрджит override поверх base."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_toml(path: Path) -> dict:
    """Загружает TOML — tomllib (3.11+) или tomli (fallback)."""
    if sys.version_info >= (3, 11):
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    try:
        import tomli  # pip install tomli
        with open(path, "rb") as f:
            return tomli.load(f)
    except ImportError:
        # Минимальный TOML-парсер для простых key = "value" и key = ["a", "b"]
        return _mini_toml(path.read_text(encoding="utf-8"))


def _mini_toml(text: str) -> dict:
    """Парсит простой TOML без вложенных таблиц глубже одного уровня."""
    import re
    result: dict = {}
    current: dict = result
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m_section = re.match(r'^\[(\w+)\]$', line)
        if m_section:
            key = m_section.group(1)
            result[key] = {}
            current = result[key]
            continue
        m_kv = re.match(r'^(\w+)\s*=\s*(.+)$', line)
        if m_kv:
            k, v = m_kv.group(1), m_kv.group(2).strip()
            if v.startswith('"') or v.startswith("'"):
                current[k] = v.strip('"\'')
            elif v.lower() == 'true':
                current[k] = True
            elif v.lower() == 'false':
                current[k] = False
            elif v.startswith('['):
                items = re.findall(r'["\']([^"\']+)["\']', v)
                current[k] = items
            else:
                try:
                    current[k] = int(v)
                except ValueError:
                    current[k] = v
    return result


def load() -> dict:
    """Загружает конфиг. Если файла нет — возвращает дефолты."""
    if not _CONFIG_PATH.exists():
        return dict(DEFAULTS)
    try:
        raw = _load_toml(_CONFIG_PATH)
        return _deep_merge(DEFAULTS, raw)
    except Exception as e:
        print(f"[lime] Ошибка чтения конфига: {e}. Используются дефолты.")
        return dict(DEFAULTS)


def get(section: str, key: str):
    """Shortcut: config.get('general', 'color')"""
    cfg = load()
    return cfg.get(section, {}).get(key, DEFAULTS.get(section, {}).get(key))
