"""Операционные задачи: python -m app.maintenance rotate|verify"""
import sys

from sqlalchemy import select

from . import audit
from .crypto_server import rewrap
from .db import AuditLog, RefreshToken, SessionLocal, User, VaultItem


def rotate_all(db) -> int:
    """Перешифровать DEK всех записей и TOTP-секретов активным KEK (данные не расшифровываются)."""
    n = 0
    for it in db.scalars(select(VaultItem)):
        it.sealed = rewrap(it.sealed, f"item|{it.user_id}|{it.id}".encode()); n += 1
    for u in db.scalars(select(User).where(User.totp_sealed.is_not(None))):
        u.totp_sealed = rewrap(u.totp_sealed, b"totp|" + u.id.encode()); n += 1
    db.commit()
    return n


def dump(db) -> None:
    """Показывает, что РЕАЛЬНО лежит в БД (для демонстрации: плейнтекста нет)."""
    print("== users ==")
    for u in db.scalars(select(User)):
        print(f"{u.email:28} auth_hash={u.auth_hash[:38]}...  wrapped_vault_key={u.wrapped_vault_key[:20]}...")
        print(f"{'':28} 2fa={'on' if u.totp_enabled else 'off'}  failed={u.failed_attempts}  locked_until={u.locked_until}")
    print("== vault_items (sealed = kek_id|wrapped_dek|AES-GCM(client_ciphertext)) ==")
    for i in db.scalars(select(VaultItem)):
        print(f"{i.id[:8]}  user={i.user_id[:8]}  v{i.version}  {len(i.sealed)}B  {i.sealed[:28].hex()}...")
    print("== refresh_tokens (хранятся только SHA-256) ==")
    for t in db.scalars(select(RefreshToken)):
        print(f"{t.token_hash[:16]}...  used={t.used} revoked={t.revoked}")
    print("== audit_log (последние 10) ==")
    for a in db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(10)):
        print(f"#{a.id:<3} {a.event:24} hash={a.hash[:12]}... prev={a.prev_hash[:12]}...")


if __name__ == "__main__":
    with SessionLocal() as db:
        if sys.argv[1:] == ["rotate"]:
            print("rewrapped:", rotate_all(db))
        elif sys.argv[1:] == ["verify"]:
            bad = audit.verify_chain(db)
            print("audit chain OK" if bad is None else f"TAMPERED at id={bad}")
            sys.exit(0 if bad is None else 1)
        elif sys.argv[1:] == ["dump"]:
            dump(db)
        else:
            print("usage: python -m app.maintenance [rotate|verify|dump]")
