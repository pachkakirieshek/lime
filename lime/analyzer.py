from .ast_parser import parse
from .graph import build, scan
from .plugins import run


def analyze(pkgbuild):
    if not pkgbuild:
        return "LOW", 0, ["no PKGBUILD"]

    risk = 0
    reasons = []

    ast = parse(pkgbuild)

    if "curl" in pkgbuild:
        risk += 80
        reasons.append("curl usage")

    if "sudo" in pkgbuild:
        risk += 60
        reasons.append("sudo usage")

    graph = build(pkgbuild)
    reasons += scan(graph)

    reasons += run(pkgbuild)

    if "package" not in ast["functions"]:
        risk += 50
        reasons.append("missing package()")

    level = (
        "Keter" if risk > 220 else
        "High" if risk > 120 else
        "Medium" if risk > 50 else
        "Low"
    )

    return level, risk, reasons
