import shutil
from .fetcher import fetch_pkgbuild
from .analyzer import analyze
from .diff import get_diff
from .sandbox import sandbox
from .report import report
from .tui import confirm


HELPERS = ["paru", "yay"]


def detect_helper():
    for h in HELPERS:
        if shutil.which(h):
            return h
    return None


def install(pkg):
    pkgbuild = fetch_pkgbuild(pkg)

    level, risk, reasons = analyze(pkgbuild)
    diff = get_diff(pkg, pkgbuild)

    print(report(pkg, level, risk, reasons, diff))

    if level in ["HIGH", "KETER"]:
        if not confirm(level, reasons):
            return

    helper = detect_helper()

    if helper:
        return sandbox([helper, "-S", pkg]).returncode

    print("No backend found")


def audit(pkg):
    pkgbuild = fetch_pkgbuild(pkg)
    level, risk, reasons = analyze(pkgbuild)
    diff = get_diff(pkg, pkgbuild)

    print(report(pkg, level, risk, reasons, diff))