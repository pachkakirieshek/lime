"""
Анализатор безопасности PKGBUILD.

Новое: нормализация homoglyph-символов перед анализом,
SKIP integrity детектор, pip/npm global install, unversioned .so.

Уровни риска:
    Low     0–50
    Medium  51–120
    High    121–220
    Keter   221+
"""

import re
from .ast_parser  import parse
from .graph       import build, scan
from .plugins     import run
from .homoglyph   import sanitize

WHITELIST: set[str] = {
    "neovim", "vim", "git", "wget", "curl", "python", "gcc", "make",
    "cmake", "nodejs", "npm", "rustup", "go", "clang", "llvm",
    "firefox", "chromium", "htop", "tmux", "zsh", "bash",
}


# ── Детекторы ──────────────────────────────────────────────────────────────

def _obfuscated(text: str) -> bool:
    r"""Разбитые команды: c/u/r/l, b.a.s.h и т.п.
    [\W_]+ требует хотя бы ОДИН не-буквенный символ между буквами.
    """
    patterns = [
        r"c[\W_]+u[\W_]+r[\W_]+l",
        r"w[\W_]+g[\W_]+e[\W_]+t",
        r"b[\W_]+a[\W_]+s[\W_]+h",
        r"s[\W_]+u[\W_]+d[\W_]+o",
        r"r[\W_]+m[\W_]+-[\W_]*r[\W_]*f",
    ]
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False


def _has_base64_payload(text: str) -> bool:
    """Закодированные payload'ы: base64, hex, echo|shell."""
    patterns = [
        r"base64\s*-+(d|decode)",
        r"\\x[0-9a-fA-F]{2}",
        # echo с padding (=): echo aGVsbG8= | bash
        r"echo\s+[A-Za-z0-9+/]*=+[A-Za-z0-9+/=]*\s*\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)",
        # echo с цифрой: echo aGVsbG8K0 | sh
        r"echo\s+[A-Za-z0-9+/]*[0-9][A-Za-z0-9+/]*\s*\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)",
        # echo 20+ символов: echo AAAAAAAAAAAAAAAAAAAA | bash
        r"echo\s+[A-Za-z0-9+/]{20,}\s*\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)",
        r"\$\(\s*base64",
        r"xxd\s+-r",
        r'printf\s+[\'"]\\x',
    ]
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False


def _nuclear_cmd(text: str) -> bool:
    """rm -rf / --no-preserve-root и все вариации флагов."""
    flat = re.sub(r"\s+", " ", text)
    patterns = [
        r"rm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\s+/\s*--no-preserve-root",
        r"rm\s+-r\s+-f\s+/\s*--no-preserve-root",
        r"rm\s+-f\s+-r\s+/\s*--no-preserve-root",
        r"rm\s+--recursive\s+--force\s+/\s*--no-preserve-root",
        r"rm\s+--no-preserve-root\s+\S*[rf]\S*\s+/",
        r"rm\s+--no-preserve-root\s+-r\s+-f\s+/",
    ]
    for p in patterns:
        if re.search(p, flat, re.I):
            return True
    return False


def _bad_path_outside_pkgdir(text: str, bad_path: str) -> bool:
    """Доступ к системному пути вне $pkgdir/$srcdir."""
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        if bad_path in line and "$pkgdir" not in line and "$srcdir" not in line:
            return True
    return False


def _download_exec(text: str) -> bool:
    """curl/wget напрямую в shell."""
    p = r"(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)"
    return bool(re.search(p, text, re.I))


def _reverse_shell(text: str) -> bool:
    """Reverse shell: /dev/tcp, IP в shell-команде, socket.connect."""
    patterns = [
        r"/dev/tcp/", r"/dev/udp/",
        r"(?:bash|python|perl|ruby|php|nc)\s+.*(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        r"socket\.connect\s*\(",
    ]
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False


def _ld_preload_attack(text: str) -> bool:
    p = r"/etc/ld\.so\.(conf|preload)|LD_PRELOAD\s*="
    return bool(re.search(p, text, re.I))


def _persistence(text: str) -> bool:
    p = r"/etc/(?:profile\.d|environment|rc\.local|init\.d|cron\.d|crontab)\b"
    return bool(re.search(p, text, re.I))


def _binary_download(text: str) -> bool:
    p = r"(?:curl|wget)\s+.*\.(?:sh|py|pl|rb|exe|elf|bin)\b"
    return bool(re.search(p, text, re.I))


def _self_modifying(text: str) -> bool:
    """PKGBUILD перезаписывает сам себя."""
    p1 = r"(?:>>?|tee)\s+\.?\.?/?PKGBUILD\b"
    p2 = r"PKGBUILD\b.*?[>|]"
    return bool(re.search(p1, text, re.I)) or bool(re.search(p2, text, re.I))


def _no_integrity(text: str) -> bool:
    """source=() без контрольных сумм."""
    has_source = bool(re.search(r"source\s*=\s*\(", text, re.I))
    has_hash   = bool(re.search(r"(?:md5|sha(?:1|224|256|384|512)|b2)sums\s*=", text, re.I))
    return has_source and not has_hash


def _skip_integrity(text: str) -> bool:
    """Контрольные суммы явно выставлены в SKIP — обход верификации."""
    return bool(re.search(
        r"(?:md5|sha\d+|b2)sums\s*=\s*\([^)]*['\"]SKIP['\"]",
        text, re.I
    ))


def _vcs_no_pkgver(text: str) -> bool:
    """VCS-пакет без pkgver()."""
    is_vcs = bool(re.search(r'source\s*=\s*\(.*?::(?:git|svn|hg|bzr)\+', text, re.I | re.S))
    has_fn = bool(re.search(r"pkgver\s*\(\s*\)", text))
    return is_vcs and not has_fn


def _suspicious_source_url(text: str) -> list[str]:
    """URL в source=() с неизвестным доменом."""
    urls = re.findall(r"https?://[^\s'\")\]]+", text)
    safe = re.compile(
        r"(?:github\.com|gitlab\.com|bitbucket\.org|gnu\.org|kernel\.org|"
        r"freedesktop\.org|python\.org|apache\.org|mozilla\.org|"
        r"archlinux\.org|sourceforge\.net|launchpad\.net|cpan\.org|"
        r"hackage\.haskell\.org|rubygems\.org|pypi\.org|npmjs\.com|"
        r"qt\.io|kde\.org|gnome\.org|xorg\.org|llvm\.org|"
        r"savannah\.gnu\.org|savannah\.nongnu\.org|ftp\.gnu\.org|"
        r"download\.kde\.org|download\.gnome\.org)", re.I
    )
    return [u for u in urls if not safe.search(u)]


def _pip_npm_global(text: str) -> bool:
    """pip install без --user, npm install -g — пишут в системные пути."""
    p_pip = r"pip\s+install\b(?!\s+--user)(?!\s+.*\$VIRTUAL_ENV)"
    p_npm = r"npm\s+(?:install|i)\s+-g\b"
    return bool(re.search(p_pip, text, re.I)) or bool(re.search(p_npm, text, re.I))


def _unversioned_solib(text: str) -> bool:
    """Установка .so без версии в имени — ломает ABI."""
    # install libevil.so без libevil.so.1 — плохо
    p = r"install\s+.*\blib\w+\.so\b(?!\.\d)"
    return bool(re.search(p, text))


# ── Главная функция ────────────────────────────────────────────────────────

def analyze(
    pkgbuild: str | None,
    pkg_name: str = "",
    aur_findings: list[tuple[str, int, str]] | None = None,
) -> tuple[str, int, list[str], list[str]]:
    """
    Возвращает: (level, risk_score, reasons, explanations)

    aur_findings — опциональный список из aur_meta.check_aur_reputation()
                   передаётся из core.py чтобы не делать лишний HTTP-запрос
    """
    if not pkgbuild:
        return "Low", 0, ["нет PKGBUILD"], ["PKGBUILD отсутствует или пуст."]

    if pkg_name.lower() == "max-bin":
        return (
            "Keter", 100_000,
            ["OH NO THIS IS MAX"],
            ["OH NO THIS IS MAX — этот пакет является легендарно опасным бинарником. Немедленно бегите."],
        )

    risk = 0
    reasons:      list[str] = []
    explanations: list[str] = []

    def add(reason: str, score: int, explanation: str) -> None:
        nonlocal risk
        risk += score
        reasons.append(reason)
        explanations.append(explanation)

    ast_data = parse(pkgbuild)

    # НОВОЕ: нормализуем homoglyph-символы перед анализом
    # Это исправляет обход через сurl (кириллическая с) и ｃurl (fullwidth)
    text = sanitize(pkgbuild)

    # Вычисляем флаги один раз
    obfuscated = _obfuscated(text)
    nuclear    = _nuclear_cmd(text)
    dl_exec    = _download_exec(text)

    # ── Угрозы по убыванию серьёзности ──────────────────────────────────

    if nuclear:
        add("💀 rm -rf / --no-preserve-root", 100_000,
            "КРИТИЧНО: команда уничтожения всей файловой системы.")

    if _reverse_shell(text):
        add("reverse shell", 250,
            "Признаки reverse shell (/dev/tcp, IP+порт). "
            "Пакет пытается подключиться к внешнему серверу для удалённого управления.")

    if _self_modifying(text):
        add("PKGBUILD модифицирует себя", 200,
            "PKGBUILD перезаписывает сам себя. "
            "Классический признак трояна, добавляющего код после проверки.")

    if _has_base64_payload(text):
        add("base64/hex payload", 200,
            "Закодированный блок передаётся в shell. "
            "Способ спрятать вредоносный код от анализаторов.")

    if obfuscated:
        add("обфусцированные команды (c/u/r/l и т.п.)", 150,
            "Команды разбиты символами чтобы обойти анализаторы.")

    if _ld_preload_attack(text):
        add("LD_PRELOAD / ld.so.preload", 160,
            "Модификация загрузчика библиотек — позволяет внедрить код в любой процесс.")

    if dl_exec:
        add("curl/wget | shell", 180,
            "Содержимое URL передаётся напрямую в shell без сохранения.")

    if _binary_download(text) and not dl_exec:
        add("загрузка исполняемого файла (.sh/.bin/.elf/…)", 100,
            "Пакет скачивает готовый бинарник — содержимое нельзя проверить без запуска.")

    if _persistence(text):
        add("запись в /etc/profile.d или /etc/environment", 120,
            "Регистрация автозапуска — код выполнится при каждом входе в систему.")

    if re.search(r"\bcurl\b", text) and not obfuscated and not dl_exec:
        add("curl", 80, "Пакет скачивает внешние ресурсы во время сборки.")

    if re.search(r"\bwget\b", text) and not obfuscated and not dl_exec:
        add("wget", 80, "Пакет скачивает что-то из сети во время сборки.")

    if re.search(r"\bsudo\b", text) and not nuclear:
        add("sudo", 60, "PKGBUILD не должен использовать sudo.")

    if re.search(r"\beval\b", text):
        add("eval", 90, "Динамическое выполнение строки как кода.")

    if re.search(r"(?:^|[;&|`({\s])exec\s", text, re.M):
        add("exec", 70, "Замена текущего процесса — может скрывать вредоносный код.")

    # ── НОВЫЕ детекторы ─────────────────────────────────────────────────

    # pip/npm глобальная установка
    if _pip_npm_global(text):
        add("pip/npm global install", 80,
            "pip install без --user или npm install -g пишут в системные пути. "
            "В PKGBUILD следует использовать --user или устанавливать в $pkgdir.")

    # SKIP в контрольных суммах
    if _skip_integrity(text):
        add("контрольные суммы = SKIP", 90,
            "Один или несколько файлов помечены SKIP в контрольных суммах. "
            "Целостность этих файлов не проверяется — они могут быть подменены.")

    # Ненормализованные .so
    if _unversioned_solib(text):
        add("установка .so без SONAME версии", 40,
            "Библиотека устанавливается без номера версии в имени (libfoo.so вместо libfoo.so.1). "
            "Это может сломать ABI-совместимость с другими пакетами.")

    # ── Системные пути ───────────────────────────────────────────────────
    for bad_path, score in [
        ("/etc/passwd", 100), ("/etc/shadow", 100),
        ("/etc/sudoers", 100), ("/boot", 80), ("/sys", 60), ("/proc", 50),
    ]:
        if _bad_path_outside_pkgdir(text, bad_path):
            add(f"обращение к {bad_path}", score,
                f"Прямое обращение к {bad_path} вне $pkgdir/$srcdir.")

    # ── chmod ────────────────────────────────────────────────────────────
    if re.search(r"chmod\s+([24][0-7]{3}|[ugo]\+s)", text):
        add("setuid/setgid бит", 80,
            "Файл будет запускаться с повышенными правами.")

    if re.search(r"chmod\s+(?:777|a\+rwx)", text):
        add("chmod 777", 50, "Права 777 — полный доступ для всех.")

    # ── Зависимости ──────────────────────────────────────────────────────
    graph = build(pkgbuild)
    for nr in scan(graph):
        add(nr, 30, f"Зависимость содержит сетевой инструмент ({nr}).")

    # ── Плагины ──────────────────────────────────────────────────────────
    for finding in run(pkgbuild):
        add(finding.reason, finding.score, finding.explanation)

    # ── Структура PKGBUILD ───────────────────────────────────────────────
    if "package" not in ast_data["functions"]:
        add("отсутствует функция package()", 50,
            "Нарушение структуры PKGBUILD — возможно нештатный файл.")

    if re.search(r"\.install\b", text):
        add(".install скрипт", 40,
            "Выполняется с правами root при установке/удалении.")

    # ── AUR-специфика ────────────────────────────────────────────────────
    if _no_integrity(text):
        add("source без контрольных сумм", 60,
            "Скачанные файлы нельзя проверить на целостность.")

    if _vcs_no_pkgver(text):
        add("VCS-пакет без pkgver()", 30,
            "Версия пакета не обновится при pull из репозитория.")

    sus_urls = _suspicious_source_url(text)
    for url in sus_urls[:3]:
        add(f"подозрительный URL: {url}", 70,
            f"URL {url!r} не из известного доверенного хостинга.")

    if re.search(r"BUILDENV\s*=\s*\([^)]*!(?:check|sign)", text):
        add("BUILDENV отключает проверки", 50,
            "Пакет сам отключает !check или !sign.")

    # ── AUR reputation (из aur_meta, опционально) ────────────────────────
    if aur_findings:
        for reason, score, explanation in aur_findings:
            add(reason, score, explanation)

    # ── Уровень ──────────────────────────────────────────────────────────
    level = (
        "Keter"  if risk > 220 else
        "High"   if risk > 120 else
        "Medium" if risk > 50  else
        "Low"
    )

    level_explain = {
        "Low":    "Явных угроз не обнаружено. Автоматический анализ не даёт 100% гарантии.",
        "Medium": "Обнаружены подозрительные паттерны. Рекомендуется ручная проверка.",
        "High":   "Серьёзные подозрительные паттерны! Настоятельно рекомендуется ручная проверка.",
        "Keter":  "ЭКСТРЕМАЛЬНАЯ ОПАСНОСТЬ. Пакет вероятно вредоносен. Установка крайне не рекомендуется.",
    }
    explanations.append(f"[Итог] {level_explain[level]}")

    return level, risk, reasons, explanations
