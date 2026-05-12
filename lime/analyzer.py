"""
Анализатор безопасности PKGBUILD.

Уровни риска:
    Low     0–50
    Medium  51–120
    High    121–220
    Keter   221+
"""

import re
from .ast_parser import parse
from .graph import build, scan
from .plugins import run

# ---------------------------------------------------------------------------
# Белый список — пакеты пропускаются без анализа
# ---------------------------------------------------------------------------
WHITELIST: set[str] = {
    "neovim", "vim", "git", "wget", "curl", "python", "gcc", "make",
    "cmake", "nodejs", "npm", "rustup", "go", "clang", "llvm",
    "firefox", "chromium", "htop", "tmux", "zsh", "bash",
}

# ---------------------------------------------------------------------------
# Вспомогательные детекторы
# ---------------------------------------------------------------------------

def _obfuscated(text: str) -> bool:
    r"""Разбитые команды: c/u/r/l, b.a.s.h и т.п.
    [\W_]+ — требует хотя бы ОДИН не-буквенный символ между каждой буквой.
    Без этого 'bash' и 'curl' сами по себе давали ложные срабатывания.
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
    """Закодированные payload'ы передаваемые в shell.

    Три паттерна для echo|shell чтобы покрыть:
      - строки с padding (=)  : echo aGVsbG8= | bash
      - строки с цифрой       : echo aGVsbG8K0 | sh
      - длинные строки 20+    : echo AAAAAAAAAAAAAAAAAAAA | bash
    Это лучше чем старый {6,} который ловил 'echo status | sh'.
    """
    p_b64_pad  = r"echo\s+[A-Za-z0-9+/]*=+[A-Za-z0-9+/=]*\s*\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)"
    p_b64_dig  = r"echo\s+[A-Za-z0-9+/]*[0-9][A-Za-z0-9+/]*\s*\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)"
    p_b64_long = r"echo\s+[A-Za-z0-9+/]{20,}\s*\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)"

    patterns = [
        r"base64\s*-+(d|decode)",
        # hex escape \x41 в shell-тексте — буквальный backslash+x
        r"\\x[0-9a-fA-F]{2}",
        p_b64_pad,
        p_b64_dig,
        p_b64_long,
        r"\$\(\s*base64",
        r"xxd\s+-r",
        # printf "\x41" — кавычка, затем буквальный \x
        r'printf\s+[\'"]\\x',
    ]
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False


def _nuclear_cmd(text: str) -> bool:
    """sudo rm -rf / --no-preserve-root и все вариации флагов.

    Убран первый жадный паттерн из предыдущей версии —
    он вызывал катастрофический backtracking на длинных строках.
    """
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
    """Проверяет обращение к системному пути вне $pkgdir/$srcdir.

    Исправляет ложные срабатывания для:
      install -D file "$pkgdir/boot/grub/grub.cfg"  <- легитимно
      # reads /proc/cpuinfo                          <- комментарий
      cat /proc/cpuinfo                             <- подозрительно
    """
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        if bad_path in line and "$pkgdir" not in line and "$srcdir" not in line:
            return True
    return False


def _download_exec(text: str) -> bool:
    """curl/wget передаёт результат напрямую в shell — без сохранения файла."""
    p = r"(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh|python|perl|ruby|dash|zsh)"
    return bool(re.search(p, text, re.I))


def _reverse_shell(text: str) -> bool:
    """Reverse shell паттерны: /dev/tcp, nc с IP, python/perl socket."""
    patterns = [
        r"/dev/tcp/",
        r"/dev/udp/",
        r"(?:bash|python|perl|ruby|php|nc)\s+.*(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        r"socket\.connect\s*\(",
    ]
    for p in patterns:
        if re.search(p, text, re.I):
            return True
    return False


def _ld_preload_attack(text: str) -> bool:
    """Внедрение через загрузчик библиотек."""
    p = r"/etc/ld\.so\.(conf|preload)|LD_PRELOAD\s*="
    return bool(re.search(p, text, re.I))


def _persistence(text: str) -> bool:
    """Запись в пути автозапуска: /etc/profile.d, /etc/environment и т.п."""
    p = r"/etc/(?:profile\.d|environment|rc\.local|init\.d|cron\.d|crontab)\b"
    return bool(re.search(p, text, re.I))


def _binary_download(text: str) -> bool:
    """Прямая загрузка готового исполняемого файла."""
    p = r"(?:curl|wget)\s+.*\.(?:sh|py|pl|rb|exe|elf|bin)\b"
    return bool(re.search(p, text, re.I))


def _self_modifying(text: str) -> bool:
    """PKGBUILD модифицирует сам себя — признак трояна."""
    p1 = r"(?:>>?|tee)\s+\.?\.?/?PKGBUILD\b"
    p2 = r"PKGBUILD\b.*?[>|]"
    return bool(re.search(p1, text, re.I)) or bool(re.search(p2, text, re.I))


def _no_integrity(text: str) -> bool:
    """source=() без контрольных сумм — нельзя проверить целостность файлов."""
    has_source = bool(re.search(r"source\s*=\s*\(", text, re.I))
    has_hash = bool(re.search(r"(?:md5|sha(?:1|224|256|384|512)|b2)sums\s*=", text, re.I))
    return has_source and not has_hash


def _vcs_no_pkgver(text: str) -> bool:
    """VCS-пакет (git/svn/hg) без функции pkgver() — не обновляется корректно."""
    is_vcs = bool(re.search(r'source\s*=\s*\(.*?::(?:git|svn|hg|bzr)\+', text, re.I | re.S))
    has_pkgver_fn = bool(re.search(r"pkgver\s*\(\s*\)", text))
    return is_vcs and not has_pkgver_fn


def _suspicious_source_url(text: str) -> list[str]:
    """URL в source=() с нестандартным/подозрительным доменом."""
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


# ---------------------------------------------------------------------------
# Главная функция
# ---------------------------------------------------------------------------

def analyze(pkgbuild: str | None, pkg_name: str = "") -> tuple[str, int, list[str], list[str]]:
    """Возвращает: (level, risk_score, reasons, explanations)"""

    if not pkgbuild:
        return "Low", 0, ["нет PKGBUILD"], ["PKGBUILD отсутствует или пуст — нечего анализировать."]

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
        risk    += score
        reasons.append(reason)
        explanations.append(explanation)

    ast_data   = parse(pkgbuild)
    text       = pkgbuild

    # Вычисляем один раз — раньше obfuscated вычислялся ДВАЖДЫ (был баг)
    obfuscated = _obfuscated(text)
    nuclear    = _nuclear_cmd(text)
    dl_exec    = _download_exec(text)

    # ── ЯДЕРНАЯ УГРОЗА ──────────────────────────────────────────────────
    if nuclear:
        add("💀 rm -rf / --no-preserve-root", 100_000,
            "КРИТИЧНО: команда уничтожения всей файловой системы. "
            "Сотрёт ВСЁ на диске без возможности восстановления.")

    # ── REVERSE SHELL ───────────────────────────────────────────────────
    if _reverse_shell(text):
        add("reverse shell", 250,
            "Найдены признаки reverse shell (/dev/tcp, IP+порт в shell-команде). "
            "Пакет пытается открыть соединение к внешнему серверу для удалённого управления.")

    # ── SELF-MODIFYING PKGBUILD ─────────────────────────────────────────
    if _self_modifying(text):
        add("PKGBUILD модифицирует себя", 200,
            "PKGBUILD перезаписывает или дополняет сам себя. "
            "Классический признак трояна, добавляющего код после первоначальной проверки.")

    # ── ОБФУСКАЦИЯ ───────────────────────────────────────────────────────
    if obfuscated:
        add("обфусцированные команды (c/u/r/l и т.п.)", 150,
            "Команды разбиты символами, чтобы обойти анализаторы. "
            "Классический признак вредоносного кода.")

    # ── BASE64 / HEX PAYLOAD ────────────────────────────────────────────
    if _has_base64_payload(text):
        add("base64/hex payload", 200,
            "Найден закодированный блок, передаваемый в shell. "
            "Распространённый способ спрятать вредоносный код.")

    # ── СКАЧИВАНИЕ + НЕМЕДЛЕННОЕ ВЫПОЛНЕНИЕ ─────────────────────────────
    if dl_exec:
        add("curl/wget | shell (скачать и выполнить)", 180,
            "Содержимое URL передаётся напрямую в shell без сохранения. "
            "Невозможно проверить что именно будет выполнено.")

    # ── ПРЯМАЯ ЗАГРУЗКА БИНАРНИКА ───────────────────────────────────────
    if _binary_download(text) and not dl_exec:
        add("загрузка исполняемого файла (.sh/.bin/.elf/…)", 100,
            "Пакет скачивает готовый бинарник. "
            "Содержимое нельзя проверить без запуска — возможен trojan.")

    # ── LD_PRELOAD АТАКА ─────────────────────────────────────────────────
    if _ld_preload_attack(text):
        add("LD_PRELOAD / ld.so.preload", 160,
            "Модификация загрузчика разделяемых библиотек. "
            "Позволяет внедрить произвольный код в любой процесс системы.")

    # ── PERSISTENCE ──────────────────────────────────────────────────────
    if _persistence(text):
        add("запись в /etc/profile.d или /etc/environment", 120,
            "Пакет регистрирует автозапуск через системные init-пути. "
            "Код будет выполняться при каждом входе пользователя или старте системы.")

    # ── CURL / WGET (без pipe) ───────────────────────────────────────────
    if re.search(r"\bcurl\b", text) and not obfuscated and not dl_exec:
        add("curl", 80,
            "Пакет скачивает внешние ресурсы во время сборки. "
            "Стоит проверить откуда идёт загрузка и что именно скачивается.")

    if re.search(r"\bwget\b", text) and not obfuscated and not dl_exec:
        add("wget", 80,
            "Пакет скачивает что-то из сети во время сборки.")

    # ── SUDO ─────────────────────────────────────────────────────────────
    if re.search(r"\bsudo\b", text) and not nuclear:
        add("sudo", 60,
            "PKGBUILD не должен использовать sudo — makepkg уже даёт нужные права. "
            "Лишний sudo в PKGBUILD подозрителен.")

    # ── EVAL ─────────────────────────────────────────────────────────────
    if re.search(r"\beval\b", text):
        add("eval", 90,
            "Динамическое выполнение строки как кода. "
            "Часто используется для скрытия вредоносных команд.")

    # ── EXEC (только как команда, не как часть слова) ────────────────────
    # Исправлен баг: \bexec\b ловило 'install --exec=0755' и 'exec_prefix'
    if re.search(r"(?:^|[;&|`({\s])exec\s", text, re.M):
        add("exec", 70,
            "Найден exec — замена текущего процесса другим процессом. "
            "Может использоваться для скрытого запуска кода.")

    # ── СЕТЕВЫЕ ЗАВИСИМОСТИ ──────────────────────────────────────────────
    graph = build(pkgbuild)
    for nr in scan(graph):
        add(nr, 30, f"Зависимость содержит сетевой инструмент ({nr}).")

    # ── ПЛАГИНЫ ──────────────────────────────────────────────────────────
    for finding in run(pkgbuild):
        add(finding.reason, finding.score, finding.explanation)

    # ── ОТСУТСТВУЕТ package() ────────────────────────────────────────────
    if "package" not in ast_data["functions"]:
        add("отсутствует функция package()", 50,
            "Стандартная функция package() не найдена. "
            "Нарушение структуры PKGBUILD — возможно нештатный файл.")

    # ── .INSTALL СКРИПТЫ ─────────────────────────────────────────────────
    if re.search(r"\.install\b", text):
        add(".install скрипт", 40,
            "Пакет содержит .install скрипт, выполняемый с правами root "
            "при установке/удалении. Рекомендуется проверить его отдельно.")

    # ── СИСТЕМНЫЕ ПУТИ (только вне $pkgdir/$srcdir) ──────────────────────
    # Исправлен баг: раньше '$pkgdir/boot/...' ложно триггерило /boot
    for bad_path, score in [
        ("/etc/passwd",  100),
        ("/etc/shadow",  100),
        ("/etc/sudoers", 100),
        ("/boot",         80),
        ("/sys",          60),
        ("/proc",         50),
    ]:
        if _bad_path_outside_pkgdir(text, bad_path):
            add(f"обращение к {bad_path}", score,
                f"Прямое обращение к {bad_path} вне контекста $pkgdir/$srcdir. "
                "Изменение системных файлов напрямую — опасно.")

    # ── SETUID / CHMOD 777 ───────────────────────────────────────────────
    # Исправлен баг: [0-9]*s ловило 'chmod somevar'
    if re.search(r"chmod\s+([24][0-7]{3}|[ugo]\+s)", text):
        add("setuid/setgid бит", 80,
            "Устанавливается setuid/setgid — файл будет запускаться с повышенными правами.")

    if re.search(r"chmod\s+(?:777|a\+rwx)", text):
        add("chmod 777", 50,
            "Права 777 дают всем полный доступ к файлу.")

    # ── AUR-СПЕЦИФИЧНЫЕ ПРОВЕРКИ ─────────────────────────────────────────

    # Нет контрольных сумм — целостность файлов не проверяется
    if _no_integrity(text):
        add("source без контрольных сумм", 60,
            "В source=() есть файлы, но отсутствуют md5sums/sha256sums/b2sums. "
            "Невозможно проверить что скачанные файлы не были подменены.")

    # VCS без pkgver() — пакет не сможет корректно обновляться
    if _vcs_no_pkgver(text):
        add("VCS-пакет без pkgver()", 30,
            "Пакет использует VCS-источник (git/svn/hg), но не имеет функции pkgver(). "
            "Версия пакета не будет обновляться при обновлении репозитория.")

    # Подозрительные URL в source
    sus_urls = _suspicious_source_url(text)
    for url in sus_urls[:3]:  # не спамим если их много
        add(f"подозрительный URL: {url}", 70,
            f"URL {url!r} не принадлежит известному доверенному хостингу. "
            "Стоит вручную проверить этот источник перед установкой.")

    # PKGBUILD модифицирует свой buildenv чтобы отключить проверки
    if re.search(r"BUILDENV\s*=\s*\([^)]*!(?:check|sign)", text):
        add("BUILDENV отключает проверки", 50,
            "В BUILDENV отключены !check или !sign — пакет обходит проверку целостности.")

    # ── УРОВЕНЬ РИСКА ────────────────────────────────────────────────────
    level = (
        "Keter"  if risk > 220 else
        "High"   if risk > 120 else
        "Medium" if risk > 50  else
        "Low"
    )

    level_explain = {
        "Low":    "Явных угроз не обнаружено. Пакет выглядит безопасным — "
                  "но автоматический анализ не даёт 100% гарантии.",
        "Medium": "Обнаружены подозрительные паттерны. "
                  "Рекомендуется ручная проверка PKGBUILD перед установкой.",
        "High":   "Серьёзные подозрительные паттерны! "
                  "Настоятельно рекомендуется ручная проверка.",
        "Keter":  "ЭКСТРЕМАЛЬНАЯ ОПАСНОСТЬ. Пакет вероятно вредоносен. "
                  "Установка крайне не рекомендуется.",
    }
    explanations.append(f"[Итог] {level_explain[level]}")

    return level, risk, reasons, explanations
