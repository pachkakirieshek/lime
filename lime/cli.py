"""
CLI точка входа.

Команды:
  lime <пакет>            — установить пакет
  lime -S <пакет>         — то же самое
  lime audit <пакет>      — только анализ без установки
  lime list               — показать кэшированные пакеты
  lime update             — проверить все кэшированные пакеты на изменения
  lime purge              — очистить старый кэш

Флаги:
  --verbose / -v          — подробный вывод (с объяснениями)
  --json                  — JSON-вывод (для скриптов)
  --help / -h             — справка
"""

import sys
from .core   import install, audit, list_cached, update_check
from .cache  import purge_old
from .locale import t
from .output import _c, B, CYN, DIM, GRN


_HELP = f"""
{_c(B, 'lime')} — безопасный AUR-хелпер с анализом PKGBUILD

{_c(B, 'ИСПОЛЬЗОВАНИЕ')}
  lime <пакет>           установить пакет из AUR
  lime -S <пакет>        то же самое
  lime audit <пакет>     только анализ, без установки
  lime list              показать кэш проверенных пакетов
  lime update            проверить все кэшированные пакеты на изменения
  lime purge             очистить кэш старше 7 дней

{_c(B, 'ФЛАГИ')}
  -v, --verbose          подробные объяснения каждой находки
  --json                 вывод в JSON (для скриптов и CI)
  -h, --help             эта справка

{_c(B, 'ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ')}
  LIME_LANG=en           английский интерфейс (по умолчанию: ru)
  NO_COLOR=1             отключить цветной вывод

{_c(B, 'УРОВНИ РИСКА')}
  {_c(GRN, 'Low')}     — явных угроз не обнаружено
  ⚠ Medium — подозрительные паттерны, рекомендуется проверка
  ✗ High   — серьёзные угрозы, требуется ручная проверка
  ☠ Keter  — экстремальная опасность, установка не рекомендуется
"""


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(_HELP)
        return

    # Флаги
    verbose = "--verbose" in args or "-v" in args
    as_json = "--json" in args
    args = [a for a in args if a not in ("--verbose", "-v", "--json")]

    if not args:
        print(t("usage"))
        return

    cmd = args[0]

    # lime list
    if cmd == "list":
        list_cached()
        return

    # lime update
    if cmd == "update":
        update_check()
        return

    # lime purge
    if cmd == "purge":
        removed = purge_old()
        print(f"\n  Удалено файлов из кэша: {removed}\n")
        return

    # lime -S <пакет>
    if cmd == "-S":
        if len(args) < 2:
            print(t("usage"))
            return
        install(args[1], verbose=verbose)
        return

    # lime audit <пакет>
    if cmd == "audit":
        if len(args) < 2:
            print(t("usage"))
            return
        audit(args[1], verbose=verbose)
        return

    # lime <пакет>
    install(cmd, verbose=verbose)


if __name__ == "__main__":
    main()

