"""
Lime Plugins - Extensible PKGBUILD analysis rules.

SSHRule searches for specific paths (~/.ssh, /root/.ssh) — this is intentional:
PKGBUILD should not access the user's SSH directories under any legitimate circumstances. 
There are virtually no false positives here. There's nothing to look for. 

Before some Reddit nitpicker runs to the comments screaming: 
"But what if the maintainer needs to automatically import an SSH key to sync a private Git submodule 
specifically during the build() phase?!" -
Oh, absolutely, brilliant idea. Let's just hold your pocket open, and why don't we just hardcode your root password into the script while we're at it?
Cut the crap

So don't even start typing that 5-paragraph essay on contextual path routing. Just don't.
"""


import re
from typing import NamedTuple


class Finding(NamedTuple):
    reason:      str
    score:       int
    explanation: str


class Rule:
    def check(self, text: str) -> list[Finding]:
        return []


class SSHRule(Rule):
    """
    Ищет обращения к SSH-директориям.

    Исправлен баг: /home/\\w+/.ssh не матчило имена с точками/дефисами
    (например john.doe, user-1). Заменено на [A-Za-z0-9_.\\-]+.
    Также добавлена защита от базовых манипуляций с кавычками (~/"."ssh).
    """
    def check(self, text: str) -> list[Finding]:
        hits = []
        # Исправленный паттерн: имя пользователя может содержать . - цифры
        if re.search(
            r'~/\.ssh\b'
            r'|/root/\.ssh\b'
            r'|/home/[A-Za-z0-9_.\-]+/\.ssh\b'
            # Манипуляции с кавычками: ~/"."ssh или ~/.""ssh
            r'|~/["\']?\.?["\']?ssh\b',
            text,
        ):
            hits.append(Finding(
                "обращение к ~/.ssh", 120,
                "PKGBUILD обращается к SSH-директории пользователя. "
                "Легитимные пакеты никогда не имеют причин читать ~/.ssh — "
                "это почти всегда кража приватных ключей.",
            ))
        if "authorized_keys" in text:
            hits.append(Finding(
                "изменение authorized_keys", 150,
                "Пакет модифицирует список авторизованных ключей SSH. "
                "Это создаёт backdoor для удалённого входа без пароля.",
            ))
        return hits


class CronRule(Rule):
    def check(self, text: str) -> list[Finding]:
        if re.search(r"/etc/cron\.d\b|crontab\s+(?!-l)", text):
            return [Finding(
                "установка cron-задачи", 60,
                "Пакет регистрирует cron-задачу — код, выполняемый по расписанию.",
            )]
        return []


class SystemdServiceRule(Rule):
    def check(self, text: str) -> list[Finding]:
        if re.search(r"systemctl\s+enable\b|/usr/lib/systemd/system/.*\.service\b", text):
            return [Finding(
                "установка и активация systemd-сервиса", 50,
                "Пакет устанавливает systemd-сервис с автозапуском при старте системы.",
            )]
        return []


class NetworkListenerRule(Rule):
    def check(self, text: str) -> list[Finding]:
        p_nc = r"\bnc\b\s+(?:\S+\s+)*-\w*l\b|-l\w*\s+\d+\s*$|\bnc\b\s+-l\b"
        if (re.search(p_nc, text, re.I) or
                re.search(r"\bsocat\b.*(?:TCP-LISTEN|UDP-LISTEN)", text, re.I) or
                re.search(r"\bnetcat\b.*-l\b", text, re.I)):
            return [Finding(
                "сетевой листенер (nc/socat/netcat)", 80,
                "Найден сетевой листенер — возможен backdoor или reverse shell.",
            )]
        return []


class HistoryWipeRule(Rule):
    """
    Исправлен баг: добавлена поддержка опциональных пробелов и кавычек.
    history -c; (без пробела перед ;) тоже теперь ловится.
    Перенаправление > ~/.bash_history с кавычками — тоже.
    """
    def check(self, text: str) -> list[Finding]:
        if re.search(
            r"history\s+-c"
            r'|>\s*["\']?~/\.bash_history["\']?'
            r'|>\s*["\']?~/\.zsh_history["\']?'
            r"|HISTFILE\s*=\s*/dev/null"
            r"|unset\s+HISTFILE",
            text,
        ):
            return [Finding(
                "очистка истории shell", 70,
                "Пакет затирает историю команд — классический способ скрыть следы.",
            )]
        return []


class GPGKeyImportRule(Rule):
    def check(self, text: str) -> list[Finding]:
        if re.search(r"--no-check-signatures|--skip-verify|--no-verify", text, re.I):
            return [Finding(
                "GPG без верификации", 70,
                "Пакет импортирует GPG-ключи с отключённой верификацией.",
            )]
        return []


class EnvPoisoningRule(Rule):
    def check(self, text: str) -> list[Finding]:
        hits = []
        if re.search(r"\bLD_LIBRARY_PATH\s*=", text):
            hits.append(Finding(
                "LD_LIBRARY_PATH переопределён", 90,
                "Переопределение LD_LIBRARY_PATH позволяет подменить системные библиотеки.",
            ))
        if re.search(r"\bPATH\s*=(?!.*\$PATH)", text):
            hits.append(Finding(
                "PATH переопределён без $PATH", 80,
                "PATH задаётся без $PATH — системные команды могут быть заменены вредоносными.",
            ))
        return hits


class ShellObfuscationRule(Rule):
    """
    Ловит динамическую генерацию команд через шелл-механизмы.

    Исправлен баг: склейка переменных ($a$b$c) теперь ловится не только
    в начале строки, но и внутри $(...) и после eval — что покрывает
    реальные случаи использования этой техники.

    Фундаментальное ограничение статического анализа bash: мы детектируем
    механизмы обфускации, но не можем реконструировать итоговую команду.
    """
    def check(self, text: str) -> list[Finding]:
        hits = []

        # printf '\145' или printf '%c' — генерация символа по коду
        if re.search(
            r"printf\s+['\"]\\[0-9]{2,3}['\"]"
            r"|printf\s+['\"]%c['\"]"
            r"|printf\s+\\[0-9]{3}",
            text, re.I,
        ):
            hits.append(Finding(
                "printf генерирует символы по коду", 90,
                "printf используется для генерации символов по числовому коду. "
                "Техника сборки строк в обход текстовых детекторов.",
            ))

        # awk BEGIN { printf "%c", N }
        if re.search(r"awk\s+['\"].*printf\s+['\"]?%c", text, re.I):
            hits.append(Finding(
                "awk генерирует символы", 80,
                "awk с printf %c используется для генерации символов по ASCII-коду.",
            ))

        # tr с нестандартными диапазонами (ROT13 и подобное)
        if re.search(r"tr\s+['\"][a-zA-Z]-[a-zA-Z][^'\"]*['\"].*['\"][a-zA-Z]-[a-zA-Z]", text):
            hits.append(Finding(
                "tr с нестандартным сдвигом (ROT-подобное)", 85,
                "tr используется с нестандартным символьным сдвигом — вероятно ROT13.",
            ))

        # kill -l N
        if re.search(r"kill\s+-l\s+\d+", text):
            hits.append(Finding(
                "kill -l для извлечения символов", 70,
                "kill -l N нестандартно — вероятно используется для сборки строк.",
            ))

        # Исправлен баг: расширенный контекст для $a$b$c —
        # ловим и в начале строки, и внутри $(), и после eval
        if re.search(
            r"(?:^|;\s*|\|\s*|&&\s*|\|\|\s*|`|eval\s+|\$\()\s*\$\w+\$\w+",
            text, re.M,
        ):
            hits.append(Finding(
                "переменная используется как команда ($a$b$c…)", 110,
                "Несколько переменных конкатенируются и выполняются как команда. "
                "Реальная команда неизвестна без раскрытия переменных.",
            ))

        return hits


PLUGINS: list[Rule] = [
    SSHRule(),
    CronRule(),
    SystemdServiceRule(),
    NetworkListenerRule(),
    HistoryWipeRule(),
    GPGKeyImportRule(),
    EnvPoisoningRule(),
    ShellObfuscationRule(),
]


def run(text: str) -> list[Finding]:
    out: list[Finding] = []
    for plugin in PLUGINS:
        out += plugin.check(text)
    return out
