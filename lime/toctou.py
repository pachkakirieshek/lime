"""
Защита от TOCTOU (Time-of-Check Time-of-Use).

Не все пакеты можно собрать без network-доступа во время сборки
(некоторые скачивают исходники в build()). В таких случаях мы
 предупреждаем пользователя но не блокируем установку.
"""

import os
import re
import shutil
import hashlib
import subprocess
from pathlib import Path

VERIFIED_DIR = Path("/tmp/lime-verified")

# Валидные символы в имени AUR-пакета
_SAFE_PKG_RE = re.compile(r"^[A-Za-z0-9._+\-]+$")


def _safe_pkg_name(pkg: str) -> str:
    if not _SAFE_PKG_RE.match(pkg):
        raise ValueError(f"Небезопасное имя пакета: {pkg!r}")
    return pkg


def _ensure_verified_dir() -> None:
    """
    Создаёт VERIFIED_DIR с правами 0o700.

    Исправлен баг: без явного chmod злоумышленник мог создать
    /tmp/lime-verified/<pkg>/ заранее с другими правами и подменить PKGBUILD
    между save_verified() и запуском makepkg (новый TOCTOU внутри защиты).
    """
    VERIFIED_DIR.mkdir(exist_ok=True)
    VERIFIED_DIR.chmod(0o700)


def save_verified(pkg: str, pkgbuild_text: str) -> Path:
    """
    Сохраняет проверенный PKGBUILD в изолированную директорию.
    Директория создаётся с правами 0o700 — только текущий пользователь.
    """
    _ensure_verified_dir()
    pkg_dir = VERIFIED_DIR / _safe_pkg_name(pkg)
    pkg_dir.mkdir(exist_ok=True)
    pkg_dir.chmod(0o700)

    pkgbuild_path = pkg_dir / "PKGBUILD"
    pkgbuild_path.write_text(pkgbuild_text, encoding="utf-8")
    pkgbuild_path.chmod(0o600)

    digest = hashlib.sha256(pkgbuild_text.encode()).hexdigest()
    hash_path = pkg_dir / ".lime-hash"
    hash_path.write_text(digest, encoding="utf-8")
    hash_path.chmod(0o600)

    return pkg_dir


def get_verified_hash(pkg: str) -> str | None:
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
    Устанавливает пакет из проверенного PKGBUILD через makepkg.

    makepkg читает /tmp/lime-verified/<pkg>/PKGBUILD — наш файл,
    а не скачивает из AUR заново.
    """
    if not shutil.which("makepkg"):
        return False, "makepkg не найден — установите пакет base-devel"

    pkg_dir = save_verified(pkg, pkgbuild_text)

    flags = ["-si"]
    if as_deps:
        flags.append("--asdeps")

    try:
        result = subprocess.run(["makepkg"] + flags, cwd=pkg_dir, timeout=600)
        if result.returncode == 0:
            return True, f"Пакет «{pkg}» успешно установлен из проверенного PKGBUILD."
        return False, f"makepkg завершился с кодом {result.returncode}."
    except subprocess.TimeoutExpired:
        return False, "Превышено время сборки (10 минут)."
    except Exception as e:
        return False, f"Ошибка запуска makepkg: {e}"


def pkgbuild_changed_since_analysis(pkg: str, current_text: str) -> bool:
    """Сравнивает с сохранённым хэшем — не перескачивает из AUR."""
    saved_hash = get_verified_hash(pkg)
    if saved_hash is None:
        return True
    return saved_hash != hashlib.sha256(current_text.encode()).hexdigest()
