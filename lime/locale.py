"""
Локализация lime. Язык выбирается через переменную окружения LIME_LANG.
По умолчанию — русский (ru). Поставь LIME_LANG=en для английского.
"""

import os

_LANG = os.environ.get("LIME_LANG", "ru").lower()

_STRINGS = {
    "no_backend": {
        "ru": "Не найден бэкенд (paru/yay). Установи один из них.",
        "en": "No backend found (paru/yay). Please install one.",
    },
    "pkg_not_found": {
        "ru": "Пакет «{pkg}» не найден в AUR.",
        "en": "Package '{pkg}' not found in AUR.",
    },
    "suggestions": {
        "ru": "Возможно, ты имел в виду: {suggestions}",
        "en": "Did you mean: {suggestions}",
    },
    "no_suggestions": {
        "ru": "Похожих пакетов не найдено.",
        "en": "No similar packages found.",
    },
    "abort": {
        "ru": "Установка отменена пользователем.",
        "en": "Installation aborted by user.",
    },
    "confirm_prompt": {
        "ru": "Уровень риска: {level}\nПричины: {reasons}\nВсё равно продолжить? [y/n]: ",
        "en": "Risk level: {level}\nReasons: {reasons}\nProceed anyway? [y/n]: ",
    },
    "usage": {
        "ru": "Использование: lime <пакет> | lime -S <пакет> | lime audit <пакет>",
        "en": "Usage: lime <pkg> | lime -S <pkg> | lime audit <pkg>",
    },
    "whitelist_skip": {
        "ru": "Пакет «{pkg}» в белом списке — анализ пропущен.",
        "en": "Package '{pkg}' is whitelisted — analysis skipped.",
    },
}


def t(key: str, **kwargs) -> str:
    entry = _STRINGS.get(key, {})
    text = entry.get(_LANG) or entry.get("en") or key
    return text.format(**kwargs) if kwargs else text
