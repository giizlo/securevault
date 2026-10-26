"""Tamper-evident журнал аудита: HMAC-цепочка.
hash_i = HMAC(audit_key, hash_{i-1} | ts | user | event | ip | detail).
Изменение/удаление/вставка записи ломает цепочку; без audit_key (его нет в БД)
пересчитать цепочку нельзя. В detail НЕЛЬЗЯ писать секреты."""
import hashlib
import hmac
import logging
import time
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from . import logconf
from .db import AuditLog

_echo = logging.getLogger("securevault.audit")

GENESIS = "0" * 64


def _h(prev: str, ts: int, user: Optional[str], event: str, ip: str, detail: str) -> str:
    msg = "|".join([prev, str(ts), user or "-", event, ip, detail]).encode()
    return hmac.new(settings.audit_key, msg, hashlib.sha256).hexdigest()


def log(db: Session, event: str, user_id: Optional[str] = None, ip: str = "-", detail: str = "") -> None:
    last = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    prev, ts = (last.hash if last else GENESIS), int(time.time())
    db.add(AuditLog(ts=ts, user_id=user_id, event=event, ip=ip, detail=detail,
                    prev_hash=prev, hash=_h(prev, ts, user_id, event, ip, detail)))
    db.flush()
    _echo.info(logconf.audit_line(event, user_id or "", ip, detail))


def verify_chain(db: Session) -> Optional[int]:
    """None - цепочка цела; иначе id первой испорченной записи."""
    prev = GENESIS
    for r in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        if r.prev_hash != prev or not hmac.compare_digest(r.hash, _h(prev, r.ts, r.user_id, r.event, r.ip, r.detail)):
            return r.id
        prev = r.hash
    return None
