import re


def parse(pkgbuild):
    return {
        "functions": re.findall(r"(\w+)\(\)\s*\{", pkgbuild or ""),
        "text": pkgbuild or ""
    }
