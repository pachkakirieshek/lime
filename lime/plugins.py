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
    def check(self, text: str) -> list[Finding]:
        hits = []
        if "~/.ssh" in text or "/root/.ssh" in text:
            hits.append(Finding(
                "доступ к SSH-ключам", 120,
                "Пакет обращается к директории SSH-ключей. "
                "Возможна кража приватных ключей.",
            ))
        if "authorized_keys" in text:
            hits.append(Finding(
                "изменение authorized_keys", 150,
                "Пакет модифицирует список авторизованных ключей SSH. "
                "Это создаёт backdoor для удалённого доступа.",
            ))
        return hits


class CronRule(Rule):
    def check(self, text: str) -> list[Finding]:
        # /etc/cron.d — установка файла крон-задачи
        # crontab -e / crontab path — редактирование крона
        if re.search(r"/etc/cron\.d\b|crontab\s+(?!-l)", text):
            return [Finding(
                "установка cron-задачи", 60,
                "Пакет регистрирует cron-задачу — код, выполняемый по расписанию.",
            )]
        return []


class SystemdServiceRule(Rule):
    def check(self, text: str) -> list[Finding]:
        # Только enable/install для сервисов — не просто наличие .service файла
        if re.search(r"systemctl\s+enable\b|/usr/lib/systemd/system/.*\.service\b", text):
            return [Finding(
                "установка и активация systemd-сервиса", 50,
                "Пакет устанавливает systemd-сервис с автозапуском при старте системы.",
            )]
        return []


class NetworkListenerRule(Rule):
    def check(self, text: str) -> list[Finding]:
        # Исправлен баг: старый паттерн r'\bnc\b.*-l' ловил 'nc localhost 80' (клиент)
        # Новый паттерн требует флаг -l явно как первый или отдельный флаг
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
    def check(self, text: str) -> list[Finding]:
        if re.search(
            r"history\s+-c"
            r"|>\s*~/\.bash_history"
            r"|>\s*~/\.zsh_history"
            r"|HISTFILE\s*=\s*/dev/null"
            r"|unset\s+HISTFILE",
            text
        ):
            return [Finding(
                "очистка истории shell", 70,
                "Пакет затирает историю команд — классический способ скрыть следы.",
            )]
        return []


class GPGKeyImportRule(Rule):
    """Импорт GPG-ключей без верификации — обходит проверку подписи пакетов."""
    def check(self, text: str) -> list[Finding]:
        if re.search(r"--no-check-signatures|--skip-verify|--no-verify", text, re.I):
            return [Finding(
                "GPG без верификации", 70,
                "Пакет импортирует GPG-ключи с отключённой верификацией. "
                "Позволяет принять подписанные вредоносные файлы.",
            )]
        return []


class EnvPoisoningRule(Rule):
    """Установка подозрительных переменных окружения."""
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
                "PATH задаётся без включения исходного $PATH — "
                "системные команды могут быть заменены вредоносными.",
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
]


def run(text: str) -> list[Finding]:
    out: list[Finding] = []
    for plugin in PLUGINS:
        out += plugin.check(text)
    return out
