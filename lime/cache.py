"""
Кэш PKGBUILD + метаданные анализа.

Структура /tmp/lime-cache/:
  <pkgname>        — текст PKGBUILD
  <pkgname>.meta   — JSON с {level, risk, ts, hash}
"""

import os
import re
import json
import time
import hashlib

CACHE_DIR = "/tmp/lime-cache"

_SAFE_PKG = re.compile(r"^[A-Za-z0-9._+\-]+$")


def _safe_name(pkg: str) -> str:
    """Защита от path traversal."""
    if not _SAFE_PKG.match(pkg):
        raise ValueError(f"Небезопасное имя пакета: {pkg!r}")
    return pkg


def path(pkg: str) -> str:
    return os.path.join(CACHE_DIR, _safe_name(pkg))


def save(pkg: str, data: str | None) -> None:
    """Сохраняет PKGBUILD. None игнорируется (исправление TypeError)."""
    if data is None:
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(path(pkg), "w", encoding="utf-8") as f:
        f.write(data)


def load(pkg: str) -> str | None:
    p = path(pkg)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return f.read()


def save_meta(pkg: str, level: str, risk: int) -> None:
    """Сохраняет результат анализа рядом с кэшем."""
    content = load(pkg) or ""
    meta = {
        "pkg":   pkg,
        "level": level,
        "risk":  risk,
        "ts":    int(time.time()),
        "hash":  hashlib.sha256(content.encode()).hexdigest(),
    }
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(path(pkg) + ".meta", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False)


def load_meta(pkg: str) -> dict | None:
    p = path(pkg) + ".meta"
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def pkgbuild_hash(pkg: str) -> str | None:
    """SHA-256 кэшированного PKGBUILD — для TOCTOU проверки."""
    content = load(pkg)
    if content is None:
        return None
    return hashlib.sha256(content.encode()).hexdigest()


def list_all() -> list[dict]:
    """Возвращает все записи из кэша (для 'lime list')."""
    if not os.path.exists(CACHE_DIR):
        return []
    entries = []
    for fname in os.listdir(CACHE_DIR):
        if fname.endswith(".meta"):
            fpath = os.path.join(CACHE_DIR, fname)
            try:
                with open(fpath, encoding="utf-8") as f:
                    entries.append(json.load(f))
            except Exception:
                pass
    return entries


def purge_old(max_age_days: int = 7) -> int:
    """Удаляет кэш старше max_age_days. Возвращает кол-во удалённых файлов."""
    if not os.path.exists(CACHE_DIR):
        return 0
    cutoff = time.time() - max_age_days * 86400
    removed = 0
    for fname in os.listdir(CACHE_DIR):
        fpath = os.path.join(CACHE_DIR, fname)
        if os.path.getmtime(fpath) < cutoff:
            os.remove(fpath)
            removed += 1
    return removed



