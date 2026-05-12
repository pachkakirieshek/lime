import difflib
from .cache import load, save


def get_diff(pkg: str, new: str | None) -> list[str]:
    """Сравнивает новый PKGBUILD с кэшированным. Если new is None — ничего не делаем."""
    if new is None:
        return []

    old = load(pkg)

    if not old:
        save(pkg, new)
        return []

    diff = difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="")
    seen: set[str] = set()
    warnings: list[str] = []

    def warn(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            warnings.append(msg)

    for line in diff:
        low = line.lower()
        if line.startswith("+"):
            if "curl" in low or "wget" in low:
                warn("добавлена сетевая загрузка (curl/wget)")
            if "rm -rf" in low:
                warn("добавлена деструктивная команда (rm -rf)")
            if "sudo" in low:
                warn("добавлен sudo")
            if "eval" in low:
                warn("добавлен eval")
            if "base64" in low:
                warn("добавлено base64-декодирование")

    save(pkg, new)
    return warnings
