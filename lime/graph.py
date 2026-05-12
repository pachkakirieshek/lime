import re


def build(pkgbuild: str | None) -> dict:
    """Парсит все типы зависимостей: depends, makedepends, checkdepends, optdepends."""
    if not pkgbuild:
        return {"deps": []}

    deps: list[str] = []
    # Исправлен баг: старый код парсил только depends=()
    # makedepends/checkdepends тоже могут содержать опасные инструменты
    for m in re.finditer(
        r"(?:depends|makedepends|checkdepends|optdepends)\s*=\s*\((.*?)\)",
        pkgbuild, re.S | re.I
    ):
        # optdepends имеет формат 'pkg: описание' — берём только имя пакета
        for token in m.group(1).split():
            deps.append(token.split(":")[0].strip("'\""))

    return {"deps": deps}


def scan(graph: dict) -> list[str]:
    """Ищет сетевые инструменты среди зависимостей."""
    found: set[str] = set()
    for dep in graph["deps"]:
        dep_lower = dep.lower()
        if "curl" in dep_lower or "wget" in dep_lower:
            found.add("сетевая зависимость (curl/wget)")
        if dep_lower in ("python-requests", "python-urllib3", "python-httpx"):
            found.add(f"HTTP-библиотека в зависимостях ({dep})")
    return list(found)
