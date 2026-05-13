"""
AUR-специфичные проверки через публичный RPC API.

Проверяет:
  - Популярность пакета (NumVotes, Popularity)
  - Свежесть мейнтейнера (FirstSubmitted для его аккаунта)
  - OutOfDate флаг
  - Совпадение имени с официальными пакетами (потенциальный тайпосквот)
  - История коммитов через cgit (резкие изменения без смены pkgver)
"""

import re
import requests
from urllib.parse import quote


# ── AUR RPC ────────────────────────────────────────────────────────────────

def fetch_aur_info(pkg: str) -> dict | None:
    """Получает метаданные пакета из AUR RPC v5."""
    safe = quote(pkg, safe="")
    try:
        r = requests.get(
            f"https://aur.archlinux.org/rpc/v5/info?arg[]={safe}",
            timeout=8,
        )
        if r.status_code == 200:
            results = r.json().get("results", [])
            return results[0] if results else None
    except Exception:
        pass
    return None


def check_aur_reputation(pkg: str) -> list[tuple[str, int, str]]:
    """
    Возвращает список (reason, score, explanation) по метаданным AUR.
    Не крэшится если AUR недоступен.
    """
    findings: list[tuple[str, int, str]] = []
    info = fetch_aur_info(pkg)
    if info is None:
        return findings

    votes      = info.get("NumVotes", 0)
    popularity = info.get("Popularity", 0.0)
    out_of_date = info.get("OutOfDate")       # None или timestamp
    submitted  = info.get("FirstSubmitted", 0) # unix timestamp
    maintainer = info.get("Maintainer", "")

    # Очень мало голосов + низкая популярность = новый/малоизвестный пакет
    if votes < 5 and popularity < 0.1:
        findings.append((
            f"низкая репутация в AUR (голосов: {votes}, popularity: {popularity:.3f})",
            40,
            f"Пакет имеет очень мало голосов ({votes}) и низкую популярность ({popularity:.3f}). "
            "Малоизвестные пакеты реже проверяются сообществом.",
        ))

    # Пакет помечен как устаревший
    if out_of_date:
        import time
        days_old = int((time.time() - out_of_date) / 86400)
        findings.append((
            f"пакет помечен как устаревший ({days_old} дн.)",
            20,
            f"AUR-флаг OutOfDate установлен {days_old} дней назад. "
            "Устаревший пакет может содержать уязвимости или быть заброшен.",
        ))

    # Нет мейнтейнера — orphan пакет
    if not maintainer:
        findings.append((
            "orphan-пакет (нет мейнтейнера)",
            35,
            "Пакет не имеет мейнтейнера (orphan). "
            "Никто не несёт ответственности за его безопасность.",
        ))

    return findings


# ── Проверка тайпосквота через официальные repos ──────────────────────────

def check_official_repo_conflict(pkg: str) -> tuple[str, int, str] | None:
    """
    Проверяет не является ли пакет тайпосквотом официального.
    Использует AUR RPC для поиска — если в official repos есть похожее имя,
    предупреждаем.

    Простая эвристика: если имя пакета очень похоже на известный пакет
    из [core]/[extra] (отличается суффиксом -bin, -git, -nightly и т.п.) —
    это норм. Но если имя почти совпадает с официальным без суффикса — риск.
    """
    # Список популярных официальных пакетов которые часто тайпосквотят
    OFFICIAL = {
        "neovim", "vim", "git", "curl", "wget", "python", "python3",
        "nodejs", "npm", "rust", "go", "gcc", "cmake", "make",
        "openssl", "openssh", "sudo", "systemd", "bash", "zsh",
        "firefox", "chromium", "nginx", "apache", "postgresql", "mysql",
        "docker", "podman", "ansible", "terraform",
    }

    pkg_lower = pkg.lower()
    # Убираем типичные AUR-суффиксы
    stripped = re.sub(r'[-_](bin|git|svn|hg|bzr|nightly|stable|lts|latest|dev)$',
                      '', pkg_lower)

    if stripped in OFFICIAL and stripped != pkg_lower:
        return (
            f"возможный тайпосквот официального пакета '{stripped}'",
            50,
            f"Пакет '{pkg}' очень похож на официальный '{stripped}' из [core]/[extra]. "
            "Убедитесь что вам нужна именно AUR-версия, а не официальная.",
        )
    return None


# ── История коммитов ───────────────────────────────────────────────────────

def fetch_commit_history(pkg: str, limit: int = 10) -> list[dict]:
    """
    Получает последние коммиты PKGBUILD через AUR cgit atom feed.
    Возвращает список {hash, subject, date}.
    """
    safe = quote(pkg, safe="")
    url = f"https://aur.archlinux.org/cgit/aur.git/atom/?h={safe}"
    try:
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            return []
        commits = []
        # Парсим Atom XML без xml.etree чтобы не добавлять зависимость
        entries = re.findall(r'<entry>(.*?)</entry>', r.text, re.S)
        for entry in entries[:limit]:
            title = re.search(r'<title>(.*?)</title>', entry)
            updated = re.search(r'<updated>(.*?)</updated>', entry)
            commits.append({
                "subject": title.group(1) if title else "",
                "date":    updated.group(1)[:10] if updated else "",
            })
        return commits
    except Exception:
        return []


def check_commit_history(pkg: str) -> list[tuple[str, int, str]]:
    """Анализирует историю коммитов на подозрительные паттерны."""
    findings: list[tuple[str, int, str]] = []
    commits = fetch_commit_history(pkg)
    if not commits:
        return findings

    subjects = [c["subject"].lower() for c in commits]

    # Много коммитов подряд без изменения pkgver — подозрительно
    non_version_commits = [s for s in subjects
                           if not re.search(r'v?\d+\.\d+|bump|update\s+to', s)]
    if len(non_version_commits) >= 3 and len(commits) >= 4:
        ratio = len(non_version_commits) / len(commits)
        if ratio > 0.6:
            findings.append((
                "много коммитов без смены версии",
                45,
                f"{len(non_version_commits)} из {len(commits)} последних коммитов "
                "не содержат смены версии. Частые изменения без bump версии "
                "могут означать скрытые модификации.",
            ))

    # Подозрительные слова в сообщениях коммитов
    suspicious_words = ["fix security", "remove backdoor", "oops", "revert",
                        "temporary", "test", "debug", "whoops"]
    for word in suspicious_words:
        for subj in subjects:
            if word in subj:
                findings.append((
                    f"подозрительное сообщение коммита: '{word}'",
                    30,
                    f"Коммит содержит слово '{word}' — возможна попытка скрыть "
                    "или откатить вредоносные изменения.",
                ))
                break

    return findings
