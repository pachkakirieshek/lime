import difflib
from .cache import load, save


def get_diff(pkg, new):
    old = load(pkg)

    if not old:
        save(pkg, new)
        return []

    diff = difflib.unified_diff(old.splitlines(), new.splitlines())

    warnings = []

    for line in diff:
        l = line.lower()

        if line.startswith("+"):
            if "curl" in l or "wget" in l:
                warnings.append("network execution added")

            if "rm -rf" in l:
                warnings.append("destructive command added")

    save(pkg, new)

    return warnings