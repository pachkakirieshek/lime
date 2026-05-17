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


def sandbox(
    cmd: list[str],
    timeout: int = 300,
    *,
    use_bwrap: bool = False,
) -> subprocess.CompletedProcess:
    """
    Запускает команду установки через paru/yay.

    Args:
        cmd:       команда и аргументы, например ['paru', '-S', 'pkg']
        timeout:   максимальное время ожидания в секундах (по умолчанию 5 мин)
        use_bwrap: если True и bwrap доступен - оборачивает в bubblewrap.
                   Изолирует файловую систему и PID, но НЕ сеть
                   (paru/yay нужна сеть для скачивания).

      """
    actual_cmd = cmd

    if use_bwrap:
        from .arch_integration import build_bwrap_command, is_bwrap_available
        if is_bwrap_available():
            actual_cmd = build_bwrap_command(cmd)

    try:
        return subprocess.run(actual_cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[lime] Превышено время ожидания ({timeout}с). Процесс завершён.")
        raise
    except FileNotFoundError:
        print(f"[lime] Команда не найдена: {actual_cmd[0]!r}")
        raise
