import re


def build(pkgbuild):
    deps = []

    if not pkgbuild:
        return {"deps": []}

    m = re.search(r"depends=\((.*?)\)", pkgbuild, re.S)

    if m:
        deps = m.group(1).split()

    return {"deps": deps}


def scan(graph):
    bad = []

    for d in graph["deps"]:
        if "curl" in d or "wget" in d:
            bad.append("network dependency")

    return bad