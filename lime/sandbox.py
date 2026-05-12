import subprocess


def sandbox(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """Запускает команду установки.
    
    Исправлен баг: старый subprocess.run(cmd) не имел timeout и мог
    зависнуть навсегда если paru/yay завис.
    timeout=300 — 5 минут, достаточно для сборки большинства пакетов.
    """
    try:
        return subprocess.run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[lime] Превышено время ожидания ({timeout}с). Процесс завершён.")
        raise
