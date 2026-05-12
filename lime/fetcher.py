import requests
from urllib.parse import quote
from difflib import get_close_matches


def fetch_pkgbuild(pkg: str) -> str | None:
    """Возвращает текст PKGBUILD или None если пакет не существует."""
    safe_pkg = quote(pkg, safe="")  # экранируем спецсимволы в имени пакета
    url = f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={safe_pkg}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200 and r.text.strip():
            return r.text
    except requests.RequestException:
        pass
    return None


def search_similar(pkg: str, limit: int = 5) -> list[str]:
    """
    Ищет похожие пакеты в AUR через RPC.
    Возвращает список имён (до `limit` штук).
    """
    try:
        safe_pkg = quote(pkg, safe="")
        url = f"https://aur.archlinux.org/rpc/v5/search/{safe_pkg}?by=name"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            results = r.json().get("results", [])
            names = [x["Name"] for x in results]
            close = get_close_matches(pkg, names, n=limit, cutoff=0.4)
            if close:
                return close
            return names[:limit]
    except Exception:
        pass
    return []
