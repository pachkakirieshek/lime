
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
    assignments:  dict[str, str]   # переменные верхнего уровня {имя: сырое значение}
    string_lits:  list[str]        # строковые литералы в кавычках
    raw_text:     str              # исходный текст


def parse(pkgbuild: str | None) -> dict:
    """Возвращает dict для обратной совместимости с остальным кодом."""
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

    functions   = _parse_functions(text)
    assignments = _parse_assignments(text)
    string_lits = _parse_string_literals(text)

    return ParsedPKGBUILD(
        functions=functions,
        assignments=assignments,
        string_lits=string_lits,
        raw_text=text,
    )


def _parse_functions(text: str) -> list[str]:
    """
    Находит объявления функций в обоих стилях bash:
      name() {          ← стандартный POSIX
      function name() { ← с ключевым словом function
      function name {   ← без скобок (тоже валидный bash)

    Также ловит объявления на нескольких строках где { на следующей строке.
    """
    patterns = [
        # function name() { или function name() \n{
        r"^\s*function\s+(\w+)\s*\(\s*\)\s*\{?",
        # function name { (без скобок)
        r"^\s*function\s+(\w+)\s*\{",
        # name() { или name () { или name()\n{
        r"^(\w+)\s*\(\s*\)\s*\{?",
    ]
    found: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.M):
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                found.append(name)
    return found


def _parse_assignments(text: str) -> dict[str, str]:
    """
    Извлекает присвоения переменных верхнего уровня.

    Исправленные баги:
    1. Многострочные массивы: depends=(\n  curl\n  wget\n) теперь парсятся целиком.
    2. Локальные переменные внутри функций пропускаются (мы отслеживаем глубину фигурных скобок).
    3. val.strip("'\"()") заменён на правильную логику — не ломает 'curl wget' в массивах.
    """
    assignments: dict[str, str] = {}
    depth = 0  # глубина вложенности фигурных скобок

    i = 0
    lines = text.splitlines()
    while i < len(lines):
        line = lines[i]

        # Отслеживаем вложенность (упрощённо — не учитываем строки с { в кавычках)
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)

        # Только верхний уровень (вне функций)
        if depth > 0:
            i += 1
            continue

        # Однострочное присвоение: VAR=value или VAR='value' или VAR="value"
        m_simple = re.match(r'^([A-Za-z_]\w*)\s*=\s*([^\(\n].*)$', line)
        if m_simple:
            key = m_simple.group(1)
            val = m_simple.group(2).strip().strip("'\"")
            assignments[key] = val
            i += 1
            continue

        # Многострочный массив: VAR=(\n  item1\n  item2\n)
        m_array = re.match(r'^([A-Za-z_]\w*)\s*=\s*\(', line)
        if m_array:
            key = m_array.group(1)
            # Собираем строки до закрывающей скобки
            array_lines = [line]
            j = i + 1
            while j < len(lines) and ")" not in "\n".join(array_lines):
                array_lines.append(lines[j])
                j += 1
            raw_array = "\n".join(array_lines)
            # Извлекаем элементы — токены между скобками
            inner = re.search(r'\((.*?)\)', raw_array, re.S)
            if inner:
                # Токенизируем: убираем кавычки, разбиваем по пробелам/переносам
                items = re.findall(r"['\"]?([^\s'\"()]+)['\"]?", inner.group(1))
                assignments[key] = " ".join(items)
            i = j
            continue

        i += 1

    return assignments


def _parse_string_literals(text: str) -> list[str]:
    """Строковые литералы в одинарных и двойных кавычках."""
    lits: list[str] = []
    lits += re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', text)
    lits += re.findall(r"'([^']*)'", text)
    return lits

