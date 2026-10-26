"""CRUD по зашифрованным записям. Сервер видит только непрозрачные blob'ы.
Авторизация на уровне объекта: КАЖДЫЙ запрос фильтруется по user_id (защита от IDOR, OWASP API1)."""
import base64
import time

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit
from .config import settings
from .crypto_server import seal, unseal
from .db import User, VaultItem
from .deps import client_ip, current_user, get_db
from .schemas import ItemCreate, ItemUpdate

router = APIRouter(prefix="/api/v1/vault", tags=["vault"])


def _aad(user_id: str, item_id: str) -> bytes:
    return f"item|{user_id}|{item_id}".encode()


def _own(db: Session, user: User, item_id: str) -> VaultItem:
    it = db.scalar(select(VaultItem).where(VaultItem.id == item_id, VaultItem.user_id == user.id))
    if not it:
        raise HTTPException(404, "Not found")  # чужая и несуществующая запись неотличимы
    return it


def _view(db: Session, request: Request, user: User, it: VaultItem) -> dict:
    try:
        ct = unseal(it.sealed, _aad(user.id, it.id))
    except InvalidTag:  # подмена данных в БД обнаружена AEAD-тегом
        audit.log(db, "integrity_violation", user.id, client_ip(request), it.id)
        db.commit()
        raise HTTPException(500, "Data integrity error")
    return {"id": it.id, "version": it.version, "updated_at": it.updated_at,
            "ciphertext": base64.b64encode(ct).decode()}


@router.get("/items")
def list_items(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    items = db.scalars(select(VaultItem).where(VaultItem.user_id == user.id)).all()
    return [_view(db, request, user, i) for i in items]


@router.post("/items", status_code=201)
def create_item(body: ItemCreate, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    if db.scalar(select(func.count()).select_from(VaultItem).where(VaultItem.user_id == user.id)) >= settings.max_items:
        raise HTTPException(409, "Quota exceeded")
    if db.get(VaultItem, body.id):
        raise HTTPException(409, "Conflict")
    now = int(time.time())
    db.add(VaultItem(id=body.id, user_id=user.id, version=1, created_at=now, updated_at=now,
                     sealed=seal(base64.b64decode(body.ciphertext), _aad(user.id, body.id))))
    audit.log(db, "item_created", user.id, client_ip(request), body.id)
    db.commit()
    return {"id": body.id, "version": 1}


@router.get("/items/{item_id}")
def get_item(item_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _view(db, request, user, _own(db, user, item_id))


@router.put("/items/{item_id}")
def update_item(item_id: str, body: ItemUpdate, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    it = _own(db, user, item_id)
    if it.version != body.version:  # оптимистическая блокировка: нет «потерянных обновлений»
        raise HTTPException(409, "Version conflict")
    it.sealed = seal(base64.b64decode(body.ciphertext), _aad(user.id, it.id))
    it.version, it.updated_at = it.version + 1, int(time.time())
    audit.log(db, "item_updated", user.id, client_ip(request), it.id)
    db.commit()
    return {"id": it.id, "version": it.version}


@router.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: str, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    it = _own(db, user, item_id)
    db.delete(it)
    audit.log(db, "item_deleted", user.id, client_ip(request), item_id)
    db.commit()


@router.get("/audit", tags=["audit"])
def my_audit(user: User = Depends(current_user), db: Session = Depends(get_db)):
    from .db import AuditLog
    rows = db.scalars(select(AuditLog).where(AuditLog.user_id == user.id).order_by(AuditLog.id.desc()).limit(50))
    return [{"ts": r.ts, "event": r.event, "ip": r.ip} for r in rows]
