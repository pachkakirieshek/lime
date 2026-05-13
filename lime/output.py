"""
Цветной вывод для терминала.
Использует только ANSI escape-коды — нет зависимостей.
Автоматически отключает цвет если stdout не терминал (pipe, redirect).
"""

import sys
import os

# Определяем поддержку цвета
_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)

# ANSI коды
R   = "\033[0m"      # reset
B   = "\033[1m"      # bold
DIM = "\033[2m"      # dim
RED = "\033[91m"     # bright red
YEL = "\033[93m"     # bright yellow
GRN = "\033[92m"     # bright green
CYN = "\033[96m"     # bright cyan
MAG = "\033[95m"     # magenta
WHT = "\033[97m"     # white

_LEVEL_COLOR = {
    "Low":    GRN,
    "Medium": YEL,
    "High":   RED,
    "Keter":  RED + B,
}

_LEVEL_ICON = {
    "Low":    "✓",
    "Medium": "⚠",
    "High":   "✗",
    "Keter":  "☠",
}


def _c(code: str, text: str) -> str:
    """Оборачивает текст в ANSI-код если цвет включён."""
    return f"{code}{text}{R}" if _COLOR else text


def format_report(
    pkg:          str,
    level:        str,
    risk:         int,
    reasons:      list[str],
    explanations: list[str],
    diff:         list[str],
    *,
    verbose: bool = False,
) -> str:
    """Возвращает красиво отформатированный отчёт для терминала."""
    lvl_color = _LEVEL_COLOR.get(level, R)
    icon = _LEVEL_ICON.get(level, "?")
    sep = "─" * 52

    lines = [
        "",
        _c(DIM, sep),
        f" {_c(B, 'lime')} :: {_c(CYN + B, pkg)}",
        _c(DIM, sep),
        f" {'Уровень':<14} {_c(lvl_color, f'{icon}  {level}')}",
        f" {'Оценка':<14} {_c(lvl_color, str(risk))}",
    ]

    if reasons:
        lines.append("")
        lines.append(f" {_c(B, 'Обнаружено:')}")
        for i, reason in enumerate(reasons):
            expl = explanations[i] if i < len(explanations) else ""
            lines.append(f"   {_c(RED, '✗')} {reason}")
            if verbose and expl and not expl.startswith("[Итог]"):
                # Объяснение с отступом
                wrapped = _wrap(expl, width=60, indent="       ")
                lines.append(_c(DIM, wrapped))

    # Итоговое объяснение — последний элемент explanations
    if explanations:
        last = explanations[-1]
        if last.startswith("[Итог]"):
            lines.append("")
            lines.append(f" {_c(DIM, last[7:])}")  # убираем "[Итог] "

    if diff:
        lines.append("")
        lines.append(f" {_c(B, 'Изменения с прошлого раза:')}")
        for d in diff:
            lines.append(f"   {_c(YEL, '△')} {d}")

    lines.append(_c(DIM, sep))
    lines.append("")
    return "\n".join(lines)


def format_list(entries: list[dict]) -> str:
    """Форматирует вывод 'lime list'."""
    if not entries:
        return _c(DIM, "  Кэш пуст. Установите пакет: lime -S <пакет>")

    import time
    lines = [f"\n {_c(B, 'Кэшированные пакеты:')}  ({len(entries)} шт.)\n"]
    lines.append(f"  {'Пакет':<25} {'Уровень':<10} {'Оценка':<8} {'Проверен'}")
    lines.append("  " + "─" * 58)

    for e in sorted(entries, key=lambda x: x.get("risk", 0), reverse=True):
        name    = e.get("pkg", "?")
        level   = e.get("level", "?")
        risk    = e.get("risk", 0)
        ts      = e.get("ts", 0)
        age     = _age_str(ts)
        lcolor  = _LEVEL_COLOR.get(level, R)
        icon    = _LEVEL_ICON.get(level, "?")
        lines.append(
            f"  {_c(CYN, name):<25} "
            f"{_c(lcolor, f'{icon} {level}'):<10} "
            f"{_c(lcolor, str(risk)):<8} "
            f"{_c(DIM, age)}"
        )

    lines.append("")
    return "\n".join(lines)


def format_suggestions(pkg: str, suggestions: list[str]) -> str:
    """Форматирует список предложений при ненайденном пакете."""
    lines = [
        f"\n {_c(RED, '✗')} Пакет {_c(B, pkg)!r} не найден в AUR.",
    ]
    if suggestions:
        lines.append(f" {_c(YEL, '?')} Возможно, вы имели в виду:")
        for s in suggestions:
            lines.append(f"   {_c(CYN, '→')} {s}")
    else:
        lines.append(_c(DIM, "   Похожих пакетов не найдено."))
    lines.append("")
    return "\n".join(lines)


def format_whitelist_skip(pkg: str) -> str:
    return f"\n {_c(GRN, '✓')} {_c(B, pkg)} в белом списке — анализ пропущен.\n"


def format_toctou_warning(pkg: str) -> str:
    return (
        f"\n {_c(RED + B, '⚠  ВНИМАНИЕ:')} PKGBUILD пакета {_c(B, pkg)} изменился "
        f"между анализом и установкой!\n"
        f"   {_c(YEL, 'Установка прервана.')} Запустите 'lime audit {pkg}' снова.\n"
    )


# ── Вспомогательные ────────────────────────────────────────────────────────

def _wrap(text: str, width: int = 60, indent: str = "") -> str:
    """Простой word-wrap без зависимостей."""
    words = text.split()
    lines, line = [], ""
    for word in words:
        if len(line) + len(word) + 1 > width:
            lines.append(indent + line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        lines.append(indent + line)
    return "\n".join(lines)


def _age_str(ts: int) -> str:
    """Возвращает 'N минут/часов/дней назад'."""
    import time
    if not ts:
        return "никогда"
    diff = int(time.time()) - ts
    if diff < 60:
        return "только что"
    if diff < 3600:
        return f"{diff // 60} мин. назад"
    if diff < 86400:
        return f"{diff // 3600} ч. назад"
    return f"{diff // 86400} дн. назад"
