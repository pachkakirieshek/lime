import re


def parse(pkgbuild: str | None) -> dict:
    return {
        "functions": re.findall(r"(\w+)\(\)\s*\{", pkgbuild or ""),
        "text": pkgbuild or "",
    }
