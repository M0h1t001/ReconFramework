"""
Central colour/formatting helper — keeps output consistent across all modules.
Falls back to plain text automatically if colorama isn't installed.
"""
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

def _wrap(text: str, color) -> str:
    if not COLOR_ENABLED:
        return text
    return f"{color}{text}{Style.RESET_ALL}"

def info(text: str) -> str:
    return _wrap(f"[*] {text}", Fore.CYAN if COLOR_ENABLED else "")

def success(text: str) -> str:
    return _wrap(f"[+] {text}", Fore.GREEN if COLOR_ENABLED else "")

def warning(text: str) -> str:
    return _wrap(f"[-] {text}", Fore.YELLOW if COLOR_ENABLED else "")

def critical(text: str) -> str:
    return _wrap(f"[CRITICAL] {text}", Fore.RED + Style.BRIGHT if COLOR_ENABLED else "")

def header(text: str) -> str:
    return _wrap(f"\n{'=' * 60}\n{text}\n{'=' * 60}", Fore.MAGENTA if COLOR_ENABLED else "")

