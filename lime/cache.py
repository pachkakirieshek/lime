import os

CACHE_DIR = "/tmp/lime-cache"


def path(pkg):
    return os.path.join(CACHE_DIR, pkg)


def save(pkg, data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(path(pkg), "w") as f:
        f.write(data)


def load(pkg):
    p = path(pkg)
    if not os.path.exists(p):
        return None

    with open(p) as f:
        return f.read()