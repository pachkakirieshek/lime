"""
Ядро lime — install, audit, list, update.

TOCTOU fix: после анализа PKGBUILD сохраняем его хэш.
Перед передачей в paru/yay проверяем что AUR не изменился.
"""

import os
import shutil
import hashlib
import tempfile

import requests
from urllib.parse import quote

from .fetcher  import fetch_pkgbuild, search_similar
from .analyzer import analyze, WHITELIST
from .diff     import get_diff
from .sandbox  import sandbox
from .output   import (format_report, format_list, format_suggestions,
                        format_whitelist_skip, format_toctou_warning)
from .tui      import confirm
from .cache    import save, load, save_meta, list_all, pkgbuild_hash
from .aur_meta import check_aur_reputation, check_official_repo_conflict
from .locale   import t

HELPERS = ["paru", "yay"]


def detect_helper() -> str | None:
    for h in HELPERS:
        if shutil.which(h):
            return h
    return None


def _fetch_current_hash(pkg: str) -> str | None:
    """Скачивает текущий PKGBUILD из AUR и возвращает его хэш (без кэширования)."""
    safe = quote(pkg, safe="")
    try:
        r = requests.get(
            f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={safe}",
            timeout=8,
        )
        if r.status_code == 200 and r.text.strip():
            return hashlib.sha256(r.text.encode()).hexdigest()
    except Exception:
        pass
    return None


def _toctou_check(pkg: str) -> bool:
    """
    Проверяет что PKGBUILD в AUR не изменился с момента анализа.
    Возвращает True если всё ок, False если обнаружено изменение.
    """
    cached_hash   = pkgbuild_hash(pkg)
    current_hash  = _fetch_current_hash(pkg)
    if cached_hash is None or current_hash is None:
        return True  # нет данных — пропускаем проверку
    return cached_hash == current_hash


def install(pkg: str, verbose: bool = False) -> None:
    # Белый список
    if pkg.lower() in WHITELIST:
        print(format_whitelist_skip(pkg))
        helper = detect_helper()
        if helper:
            sandbox([helper, "-S", pkg])
        else:
            print(t("no_backend"))
        return

    pkgbuild = fetch_pkgbuild(pkg)

    if pkgbuild is None:
        suggestions = search_similar(pkg)
        print(format_suggestions(pkg, suggestions))
        return

    # AUR reputation (параллельно с анализом не делаем — просто вызываем)
    aur_findings = check_aur_reputation(pkg)

    # Тайпосквот-проверка
    conflict = check_official_repo_conflict(pkg)
    if conflict:
        aur_findings.append(conflict)

    level, risk, reasons, explanations = analyze(
        pkgbuild, pkg_name=pkg, aur_findings=aur_findings
    )
    diff = get_diff(pkg, pkgbuild)

    # Сохраняем кэш и мета ДО установки
    save(pkg, pkgbuild)
    save_meta(pkg, level, risk)

    print(format_report(pkg, level, risk, reasons, explanations, diff, verbose=verbose))

    if level in ("High", "Keter"):
        if not confirm(level, reasons):
            print(t("abort"))
            return

    helper = detect_helper()
    if not helper:
        print(t("no_backend"))
        return

    # ── TOCTOU ЗАЩИТА ───────────────────────────────────────────────────
    # Проверяем что за время нашего анализа AUR не подменил PKGBUILD
    if not _toctou_check(pkg):
        print(format_toctou_warning(pkg))
        return

    sandbox([helper, "-S", pkg])


def audit(pkg: str, verbose: bool = False) -> None:
    pkgbuild = fetch_pkgbuild(pkg)

    if pkgbuild is None:
        suggestions = search_similar(pkg)
        print(format_suggestions(pkg, suggestions))
        return

    aur_findings = check_aur_reputation(pkg)
    conflict = check_official_repo_conflict(pkg)
    if conflict:
        aur_findings.append(conflict)

    level, risk, reasons, explanations = analyze(
        pkgbuild, pkg_name=pkg, aur_findings=aur_findings
    )
    diff = get_diff(pkg, pkgbuild)

    save(pkg, pkgbuild)
    save_meta(pkg, level, risk)

    print(format_report(pkg, level, risk, reasons, explanations, diff, verbose=verbose))


def list_cached() -> None:
    """lime list — показать все кэшированные пакеты."""
    entries = list_all()
    print(format_list(entries))


def update_check() -> None:
    """lime update — проверить все кэшированные пакеты на изменения."""
    entries = list_all()
    if not entries:
        print("\n  Кэш пуст.\n")
        return

    print(f"\n  Проверяю {len(entries)} пакетов...\n")
    changed = []
    for entry in entries:
        pkg = entry.get("pkg", "")
        if not pkg:
            continue
        current_hash = _fetch_current_hash(pkg)
        cached       = pkgbuild_hash(pkg)
        if current_hash and cached and current_hash != cached:
            changed.append(pkg)
            print(f"  ⚠  {pkg} — PKGBUILD изменился!")

    if not changed:
        print("  ✓  Все пакеты актуальны.\n")
    else:
        print(f"\n  Изменилось {len(changed)} пакетов. Запусти 'lime audit <пакет>' для проверки.\n")
