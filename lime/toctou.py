"""
Защита от TOCTOU (Time-of-Check Time-of-Use).

Не все пакеты можно собрать без network-доступа во время сборки
(некоторые скачивают исходники в build()). В таких случаях мы
 предупреждаем пользователя но не блокируем установку.
"""

import os
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path

VERIFIED_DIR = Path("/tmp/lime-verified")


def save_verified(pkg: str, pkgbuild_text: str) -> Path:
    """
    Сохраняет проверенный PKGBUILD в изолированную директорию.
    Возвращает путь к директории с PKGBUILD.
    """
    pkg_dir = VERIFIED_DIR / _safe_pkg_name(pkg)
    pkg_dir.mkdir(parents=True, exist_ok=True)

    pkgbuild_path = pkg_dir / "PKGBUILD"
    pkgbuild_path.write_text(pkgbuild_text, encoding="utf-8")

    # Сохраняем хэш для последующей проверки
    digest = hashlib.sha256(pkgbuild_text.encode()).hexdigest()
    (pkg_dir / ".lime-hash").write_text(digest, encoding="utf-8")

    return pkg_dir


def get_verified_hash(pkg: str) -> str | None:
    """Возвращает хэш сохранённого проверенного PKGBUILD."""
    hash_path = VERIFIED_DIR / _safe_pkg_name(pkg) / ".lime-hash"
    if hash_path.exists():
        return hash_path.read_text().strip()
    return None


def install_from_verified(
    pkg: str,
    pkgbuild_text: str,
    *,
    as_deps: bool = False,
) -> tuple[bool, str]:
    """
    Устанавливает пакет из проверенного PKGBUILD.

    Алгоритм:
        1. Сохраняем проверенный PKGBUILD в /tmp/lime-verified/<pkg>/
        2. Запускаем makepkg -si в этой директории
        3. makepkg читает НАШ файл, а не скачивает из AUR заново

    Returns:
        (success, message)
    """
    if not shutil.which("makepkg"):
        return False, "makepkg не найден — установите base-devel"

    pkg_dir = save_verified(pkg, pkgbuild_text)

    flags = ["-si"]
    if as_deps:
        flags.append("--asdeps")

    try:
        result = subprocess.run(
            ["makepkg"] + flags,
            cwd=pkg_dir,
            timeout=600,
        )
        if result.returncode == 0:
            return True, f"Пакет «{pkg}» успешно установлен из проверенного PKGBUILD."
        else:
            return False, f"makepkg завершился с кодом {result.returncode}."
    except subprocess.TimeoutExpired:
        return False, "Превышено время сборки (10 минут)."
    except Exception as e:
        return False, f"Ошибка: {e}"


def pkgbuild_changed_since_analysis(pkg: str, current_text: str) -> bool:
    """
    Проверяет изменился ли PKGBUILD с момента анализа.
    Сравнивает с сохранённым проверенным файлом, а не перескачивает из AUR.
    """
    saved_hash = get_verified_hash(pkg)
    if saved_hash is None:
        return True  # нет сохранённого — считаем изменился
    current_hash = hashlib.sha256(current_text.encode()).hexdigest()
    return saved_hash != current_hash


def _safe_pkg_name(pkg: str) -> str:
    import re
    if not re.match(r"^[A-Za-z0-9._+\-]+$", pkg):
        raise ValueError(f"Небезопасное имя пакета: {pkg!r}")
    return pkg
