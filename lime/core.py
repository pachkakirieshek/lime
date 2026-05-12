import shutil
from .fetcher import fetch_pkgbuild, search_similar
from .analyzer import analyze, WHITELIST
from .diff import get_diff
from .sandbox import sandbox
from .report import report
from .tui import confirm
from .locale import t

HELPERS = ["paru", "yay"]


def detect_helper():
    for h in HELPERS:
        if shutil.which(h):
            return h
    return None


def install(pkg: str):
    # Белый список
    if pkg.lower() in WHITELIST:
        print(t("whitelist_skip", pkg=pkg))
        helper = detect_helper()
        if helper:
            return sandbox([helper, "-S", pkg]).returncode
        print(t("no_backend"))
        return

    pkgbuild = fetch_pkgbuild(pkg)

    # Пакет не найден
    if pkgbuild is None:
        print(t("pkg_not_found", pkg=pkg))
        suggestions = search_similar(pkg)
        if suggestions:
            print(t("suggestions", suggestions=", ".join(suggestions)))
        else:
            print(t("no_suggestions"))
        return

    level, risk, reasons, explanations = analyze(pkgbuild, pkg_name=pkg)
    diff = get_diff(pkg, pkgbuild)

    print(report(pkg, level, risk, reasons, explanations, diff))

    if level in ("High", "Keter"):
        if not confirm(level, reasons):
            print(t("abort"))
            return

    helper = detect_helper()
    if helper:
        return sandbox([helper, "-S", pkg]).returncode

    print(t("no_backend"))


def audit(pkg: str):
    pkgbuild = fetch_pkgbuild(pkg)

    if pkgbuild is None:
        print(t("pkg_not_found", pkg=pkg))
        suggestions = search_similar(pkg)
        if suggestions:
            print(t("suggestions", suggestions=", ".join(suggestions)))
        else:
            print(t("no_suggestions"))
        return

    level, risk, reasons, explanations = analyze(pkgbuild, pkg_name=pkg)
    diff = get_diff(pkg, pkgbuild)

    print(report(pkg, level, risk, reasons, explanations, diff))
