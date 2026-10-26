"""Живой лог сервера в терминал: HTTP-запросы и события аудита. Секретные значения НЕ выводятся -
только имена полей и их размеры (демонстрация принципа «не логировать секреты»)."""
import logging
import os
import sys

NO = bool(os.getenv("NO_COLOR"))
c = lambda code, s: s if NO else f"\033[{code}m{s}\033[0m"  # noqa: E731
GREEN, YELLOW, RED, CYAN, DIM, BOLD = "32", "33", "31", "36", "2", "1"


def setup() -> None:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter("%(message)s"))
    for name in ("securevault.http", "securevault.audit"):
        lg = logging.getLogger(name)
        if not lg.handlers:
            lg.addHandler(h)
        lg.setLevel(logging.INFO)
        lg.propagate = False


BAD_EVENTS = ("failed", "locked", "reuse", "violation", "duplicate")


def audit_line(event: str, user: str, ip: str, detail: str) -> str:
    col = RED if any(b in event for b in BAD_EVENTS) else GREEN
    return c(col, f"   [AUDIT] {event}") + c(DIM, f" user={(user or '-')[:8]} ip={ip} {detail}")


def http_line(ts: str, method: str, path: str, status: int, ms: float, ip: str) -> str:
    col = GREEN if status < 300 else YELLOW if status < 400 else RED
    return f"{c(DIM, ts)} {c(BOLD, f'{method:6}')} {path}  {c(col, str(status))}  {ms:.0f}ms  {c(DIM, ip)}"


def shape(body: bytes) -> str:
    """Структура тела без значений: {email:17ch, auth_key:44ch}."""
    import json
    try:
        d = json.loads(body)
        return "{" + ", ".join(f"{k}:{len(str(v))}ch" for k, v in d.items()) + "}"
    except Exception:
        return f"<{len(body)} bytes>"
