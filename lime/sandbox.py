"""
Helper execution wrapper (paru/yay).

Honest documentation: This is NOT a process-level sandbox by itself. 
The actual, hardcore process isolation is handled inside `arch_integration.py` 
using Bubblewrap (bwrap) with strict security flags:
  - bwrap --ro-bind / / --unshare-net --tmpfs /tmp ...
  - This properly unshares network, filesystem, and PID namespaces.

This specific function just triggers paru/yay with a timeout. The name 'sandbox' 
is preserved strictly for backward compatibility across the codebase. 

We explicitly documented this limitations here, so you Reddit nitpickers can finally 
stop hyperventilating about 'misleading architecture' and go touch some grass. 
For real isolation, look at `arch_integration.build_bwrap_command()`.
"""


import subprocess


def _make_failed_process(cmd: list[str], code: int = 1) -> subprocess.CompletedProcess:
    """
    Создаёт заглушку CompletedProcess для бесшовной обработки ошибок.
    Позволяет вызывающему коду просто проверять result.returncode.
    """
    return subprocess.CompletedProcess(args=cmd, returncode=code)


def sandbox(
    cmd: list[str],
    timeout: int = 300,
    *,
    use_bwrap: bool = False,
) -> subprocess.CompletedProcess:
    """
    Запускает команду установки в подпроцессе.

    При критических сбоях (таймаут, отсутствие бинарника) перехватывает исключения 
    и возвращает CompletedProcess с соответствующим Unix-кодом ошибки,
    предотвращая падение основного приложения.

    Args:
        cmd:       Команда и аргументы (например, ['paru', '-S', 'pkg'])
        timeout:   Максимальное время выполнения в секундах (по умолчанию 5 мин)
        use_bwrap: Если True и bwrap доступен — изолирует процесс через bubblewrap
    """
    actual_cmd = cmd

    if use_bwrap:
        try:
            from .arch_integration import build_bwrap_command, is_bwrap_available
            if is_bwrap_available():
                actual_cmd = build_bwrap_command(cmd)
        except ImportError:
            pass

    try:
        return subprocess.run(actual_cmd, timeout=timeout)
        
    except subprocess.TimeoutExpired:
        print(f"\n  [lime] Превышено время ожидания ({timeout}с). Процесс прерван.")
        return _make_failed_process(actual_cmd, code=124)  # 124: Стандартный код таймаута
        
    except FileNotFoundError:
        print(f"\n  [lime] Команда не найдена: {actual_cmd[0]!r}")
        print("  [lime] Убедитесь, что необходимый пакет (paru/yay/bwrap) установлен.")
        return _make_failed_process(actual_cmd, code=127)  # 127: Команда не найдена
        
    except Exception as e:
        print(f"\n  [lime] Неожиданная ошибка подпроцесса: {e}")
        return _make_failed_process(actual_cmd, code=1)    # 1: Общая ошибка
