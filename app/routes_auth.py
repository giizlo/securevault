"""Регистрация, вход, refresh-ротация, 2FA."""
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import audit
from .config import settings
from .crypto_server import seal, unseal
from .db import RefreshToken, User
from .deps import client_ip, current_user, get_db
from .ratelimit import RateLimiter
from .schemas import LoginIn, PreloginIn, RefreshIn, RegisterIn, TotpEnableIn
from .security import (DUMMY_HASH, create_access_token, fake_salt, hash_auth_key, needs_rehash,
                       new_refresh_token, new_totp_secret, sha256hex, verify_auth_key, verify_totp)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
rl_pre, rl_reg, rl_login, rl_refresh = RateLimiter(30, 60), RateLimiter(5, 60), RateLimiter(10, 60), RateLimiter(30, 60)
DEFAULT_KDF = {"time_cost": 2, "memory_cost": 19456, "parallelism": 1}


def _fail(db: Session, status: int = 401, msg: str = "Invalid credentials"):
    db.commit()  # фиксируем счётчики/аудит ДО выбрасывания исключения
    raise HTTPException(status, msg)


@router.post("/prelogin", dependencies=[Depends(rl_pre)])
def prelogin(body: PreloginIn, db: Session = Depends(get_db)):
    """Отдаёт соль и параметры KDF. Для неизвестного email - правдоподобная детерминированная
    подделка (HMAC), поэтому по ответу нельзя узнать, существует ли аккаунт."""
    u = db.scalar(select(User).where(User.email == body.email.lower()))
    if u:
        return {"kdf_salt": u.kdf_salt, "time_cost": u.kdf_time, "memory_cost": u.kdf_mem, "parallelism": u.kdf_par}
    return {"kdf_salt": fake_salt(body.email.lower()), **DEFAULT_KDF}


@router.post("/register", status_code=201, dependencies=[Depends(rl_reg)])
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    ip, email = client_ip(request), body.email.lower()
    h = hash_auth_key(body.auth_key)  # хеш считаем всегда -> одинаковое время для новых/существующих
    if db.scalar(select(User.id).where(User.email == email)):
        audit.log(db, "register_duplicate", None, ip)
        db.commit()
        return {"status": "ok"}  # одинаковый ответ -> нет перечисления
    u = User(id=str(uuid.uuid4()), email=email, kdf_salt=body.kdf_salt, kdf_time=body.kdf_time,
             kdf_mem=body.kdf_mem, kdf_par=body.kdf_par, auth_hash=h,
             wrapped_vault_key=body.wrapped_vault_key, created_at=int(time.time()))
    db.add(u)
    audit.log(db, "register", u.id, ip)
    db.commit()
    return {"status": "ok"}


def _issue(db: Session, user: User, family: str = "") -> dict:
    family = family or str(uuid.uuid4())
    raw, h = new_refresh_token()
    db.add(RefreshToken(id=str(uuid.uuid4()), user_id=user.id, family_id=family, token_hash=h,
                        expires_at=int(time.time()) + settings.refresh_ttl))
    return {"access_token": create_access_token(user.id, family), "refresh_token": raw,
            "token_type": "bearer", "expires_in": settings.access_ttl}


@router.post("/login", dependencies=[Depends(rl_login)])
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip, now = client_ip(request), int(time.time())
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    locked = bool(user and user.locked_until > now)
    # Проверка хеша выполняется ВСЕГДА (в т.ч. dummy) -> выравнивание времени, нет timing-oracle
    ok = verify_auth_key(user.auth_hash if user else DUMMY_HASH, body.auth_key)

    if not (user and ok) or locked:
        if user and not locked:
            user.failed_attempts += 1
            if user.failed_attempts >= settings.max_failed:  # экспоненциальная блокировка
                over = user.failed_attempts - settings.max_failed
                user.locked_until = now + min(settings.base_lock * 2**over, 86400)
                audit.log(db, "account_locked", user.id, ip)
        audit.log(db, "login_failed", user.id if user else None, ip)
        _fail(db)  # одинаковый ответ для: нет пользователя / неверный пароль / блокировка

    if user.totp_enabled:
        secret = unseal(user.totp_sealed, b"totp|" + user.id.encode()).decode()
        step = verify_totp(secret, body.totp, user.totp_last_step) if body.totp else None
        if body.totp is None:
            db.commit()
            raise HTTPException(401, "totp_required")  # раскрывается только после верного пароля
        if step is None:
            audit.log(db, "login_totp_failed", user.id, ip)
            _fail(db)
        user.totp_last_step = step  # одноразовость кода (anti-replay)

    user.failed_attempts, user.locked_until = 0, 0
    if needs_rehash(user.auth_hash):  # прозрачное обновление параметров Argon2
        user.auth_hash = hash_auth_key(body.auth_key)
    tokens = _issue(db, user)
    audit.log(db, "login_ok", user.id, ip)
    db.commit()
    return {**tokens, "wrapped_vault_key": user.wrapped_vault_key}


@router.post("/refresh", dependencies=[Depends(rl_refresh)])
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    """Ротация refresh-токена с обнаружением повторного использования (reuse detection)."""
    ip, now = client_ip(request), int(time.time())
    rt = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == sha256hex(body.refresh_token)))
    if not rt:
        _fail(db)
    if rt.used or rt.revoked:  # токен украден и использован дважды -> убиваем всю сессию
        db.execute(update(RefreshToken).where(RefreshToken.family_id == rt.family_id).values(revoked=1))
        audit.log(db, "refresh_reuse_detected", rt.user_id, ip)
        _fail(db)
    if rt.expires_at <= now:
        _fail(db)
    rt.used = 1
    user = db.get(User, rt.user_id)
    tokens = _issue(db, user, rt.family_id)
    audit.log(db, "token_refreshed", user.id, ip)
    db.commit()
    return tokens


@router.post("/logout")
def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(update(RefreshToken).where(RefreshToken.family_id == user._sid).values(revoked=1))  # type: ignore
    audit.log(db, "logout", user.id, client_ip(request))
    db.commit()
    return {"status": "ok"}


@router.post("/2fa/setup")
def totp_setup(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        raise HTTPException(409, "2FA already enabled")
    secret = new_totp_secret()
    user.totp_sealed = seal(secret.encode(), b"totp|" + user.id.encode())  # секрет шифруется KEK
    db.commit()
    return {"secret": secret, "otpauth_uri": f"otpauth://totp/SecureVault:{user.email}?secret={secret}&issuer=SecureVault"}


@router.post("/2fa/enable")
def totp_enable(body: TotpEnableIn, request: Request, user: User = Depends(current_user),
                db: Session = Depends(get_db)):
    if not user.totp_sealed or user.totp_enabled:
        raise HTTPException(409, "Invalid state")
    secret = unseal(user.totp_sealed, b"totp|" + user.id.encode()).decode()
    step = verify_totp(secret, body.code, user.totp_last_step)
    if step is None:
        raise HTTPException(400, "Invalid code")
    user.totp_enabled, user.totp_last_step = 1, step
    audit.log(db, "2fa_enabled", user.id, client_ip(request))
    db.commit()
    return {"status": "enabled"}
