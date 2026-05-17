
"""
PKGBUILD Parser

A full AST for bash requires tree-sitter-bash or bashlex. This module uses 
structural regex-based parsing instead — a deliberate compromise for minimal dependencies. 
The limitations are explicitly documented here, so you Reddit nitpickers can stop crying.
"""

import re
from dataclasses import dataclass, field


@dataclass
class ParsedPKGBUILD:
    """Результат структурного разбора PKGBUILD."""
    functions:    list[str]        # имена объявленных функций
    assignments:  dict[str, str]   # переменные верхнего уровня {имя: значение}
    string_lits:  list[str]        # строковые литералы в кавычках
    raw_text:     str              # исходный текст


def parse(pkgbuild: str | None) -> dict:
    """
    Возвращает dict для обратной совместимости с остальным кодом.
    Внутри использует ParsedPKGBUILD.
    """
    if not pkgbuild:
        return {"functions": [], "text": "", "assignments": {}, "string_lits": []}
    result = parse_full(pkgbuild)
    return {
        "functions":   result.functions,
        "text":        result.raw_text,
        "assignments": result.assignments,
        "string_lits": result.string_lits,
    }


def parse_full(pkgbuild: str) -> ParsedPKGBUILD:
    """Структурный разбор PKGBUILD."""
    text = pkgbuild or ""

    # Функции: name() { или name () {
    functions = re.findall(r"^(\w+)\s*\(\s*\)\s*\{", text, re.M)

    # Присвоения верхнего уровня (вне функций): VAR=value или VAR=(...)
    assignments: dict[str, str] = {}
    for m in re.finditer(
        r"^([A-Za-z_]\w*)\s*=\s*(.+)$",
        text, re.M,
    ):
        name_var, val = m.group(1), m.group(2).strip()
        # Убираем кавычки и скобки для простых значений
        val_clean = val.strip("'\"()")
        assignments[name_var] = val_clean

    # Строковые литералы в одинарных и двойных кавычках
    string_lits = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
    string_lits += re.findall(r"'([^']*)'", text)

    return ParsedPKGBUILD(
        functions=functions,
        assignments=assignments,
        string_lits=string_lits,
        raw_text=text,
    )
