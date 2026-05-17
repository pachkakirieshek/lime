"""
Lime core — install, audit, list, update, check.

TOCTOU: uses toctou.install_from_verified() — makepkg reads
our saved PKGBUILD directly without downloading the file again. 
So yeah, you Reddit nitpickers can finally stop whining.
"""

import shutil
import hashlib

import requests
from urllib.parse import quote

from .fetcher          import fetch_pkgbuild, search_similar
from .analyzer         import analyze_full, WHITELIST
from .diff             import get_diff
from .toctou           import install_from_verified, pkgbuild_changed_since_analysis
from .sandbox          import sandbox
from .output           import (format_report_full, format_list,
                                format_suggestions, format_whitelist_skip,
                                format_toctou_warning)
from .tui              import confirm
from .cache            import save, load, save_meta, list_all, pkgbuild_hash
from .aur_meta         import check_aur_reputation, check_official_repo_conflict
from .locale           import t
from .srcinfo          import fetch as fetch_srcinfo, audit as audit_srcinfo
from .arch_integration import (run_namcap, namcap_findings,
                                check_in_official_repos,
                                verify_installed_package)

HELPERS = ["paru", "yay"]


def detect_helper() -> str | None:
    for h in HELPERS:
        if shutil.which(h):
            return h
    return None


def _collect_extra_findings(pkg: str, pkgbuild: str) -> list[tuple[str, int, str]]:
    """namcap + .SRCINFO + pacman -Ss."""
    extra: list[tuple[str, int, str]] = []

    srcinfo = fetch_srcinfo(pkg)
    if srcinfo is not None:
        extra.extend(audit_srcinfo(srcinfo))

    import tempfile, os
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".PKGBUILD", delete=False, encoding="utf-8",
    ) as tmp:
        tmp.write(pkgbuild)
        tmppath = tmp.name
    try:
        warnings = run_namcap(tmppath)
        if warnings:
            extra.extend(namcap_findings(warnings))
    finally:
        try:
            os.unlink(tmppath)
        except OSError:
            pass

    official = check_in_official_repos(pkg)
    if official:
        extra.append(official)

    return extra


def install(pkg: str, verbose: bool = False) -> None:
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
        print(format_suggestions(pkg, search_similar(pkg)))
        return

    aur_findings = check_aur_reputation(pkg)
    conflict = check_official_repo_conflict(pkg)
    if conflict:
        aur_findings.append(conflict)
    aur_findings.extend(_collect_extra_findings(pkg, pkgbuild))

    result = analyze_full(pkgbuild, pkg_name=pkg, aur_findings=aur_findings)
    diff   = get_diff(pkg, pkgbuild)

    save(pkg, pkgbuild)
    save_meta(pkg, result.level, result.risk)

    print(format_report_full(result, diff, verbose=verbose))

    if result.level in ("High", "Keter"):
        if not confirm(result.level, result.reasons):
            print(t("abort"))
            return

    # Настоящий TOCTOU fix: собираем из нашего сохранённого файла
    # makepkg читает /tmp/lime-verified/<pkg>/PKGBUILD, а не скачивает из AUR
    success, msg = install_from_verified(pkg, pkgbuild)
    if not success:
        # Fallback на paru/yay с предупреждением об ограничениях
        print(f"\n  [lime] makepkg не сработал: {msg}")
        print("  [lime] Fallback: устанавливаем через paru/yay.")
        print("  [lime] ПРЕДУПРЕЖДЕНИЕ: paru/yay скачает PKGBUILD самостоятельно.")
        print("  [lime] Если это критично — установи base-devel и используй makepkg.\n")
        helper = detect_helper()
        if helper:
            sandbox([helper, "-S", pkg])
        else:
            print(t("no_backend"))
    else:
        print(f"\n  ✓  {msg}\n")


def audit(pkg: str, verbose: bool = False) -> None:
    pkgbuild = fetch_pkgbuild(pkg)
    if pkgbuild is None:
        print(format_suggestions(pkg, search_similar(pkg)))
        return

    aur_findings = check_aur_reputation(pkg)
    conflict = check_official_repo_conflict(pkg)
    if conflict:
        aur_findings.append(conflict)
    aur_findings.extend(_collect_extra_findings(pkg, pkgbuild))

    result = analyze_full(pkgbuild, pkg_name=pkg, aur_findings=aur_findings)
    diff   = get_diff(pkg, pkgbuild)

    save(pkg, pkgbuild)
    save_meta(pkg, result.level, result.risk)

    print(format_report_full(result, diff, verbose=verbose))


def verify(pkg: str) -> None:
    """lime verify — целостность установленного пакета через pacman -Qk."""
    print(f"\n  Проверяю целостность «{pkg}»…\n")
    findings = verify_installed_package(pkg)
    if not findings:
        print(f"  ✓  Пакет «{pkg}» не изменён.\n")
        return
    for reason, score, explanation in findings:
        print(f"  ⚠  {reason}")
        print(f"     {explanation}\n")


def list_cached() -> None:
    print(format_list(list_all()))


def update_check() -> None:
    entries = list_all()
    if not entries:
        print("\n  Кэш пуст.\n")
        return
    print(f"\n  Проверяю {len(entries)} пакетов…\n")
    changed = []
    for entry in entries:
        pkg = entry.get("pkg", "")
        if not pkg:
            continue
        current_pb = fetch_pkgbuild(pkg)
        if current_pb and pkgbuild_changed_since_analysis(pkg, current_pb):
            changed.append(pkg)
            print(f"  ⚠  {pkg} — PKGBUILD изменился!")
    if not changed:
        print("  ✓  Все пакеты актуальны.\n")
    else:
        print(f"\n  Изменилось {len(changed)} пакетов. "
              "Запусти 'lime audit <пакет>' для проверки.\n")
