import requests

def fetch_pkgbuild(pkg):
    url = f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg}"

    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        return None