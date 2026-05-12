import os
import re

CACHE_DIR = "/tmp/lime-cache"

# Допустимые символы в имени AUR-пакета: буквы, цифры, дефис, точка, подчёркивание, плюс
_SAFE_PKG = re.compile(r"^[A-Za-z0-9._+\-]+$")


def _safe_name(pkg: str) -> str:
    """Валидирует имя пакета. Выбрасывает ValueError при подозрении на path traversal."""
    if not _SAFE_PKG.match(pkg):
        raise ValueError(f"Небезопасное имя пакета для кэша: {pkg!r}")
    return pkg


def path(pkg: str) -> str:
    return os.path.join(CACHE_DIR, _safe_name(pkg))


def save(pkg: str, data: str | None) -> None:
    """Сохраняет PKGBUILD в кэш. Если data is None — ничего не делает."""
    if data is None:          # <-- ИСПРАВЛЕНИЕ: не пишем None в файл
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
