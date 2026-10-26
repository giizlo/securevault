"""Криптографические примитивы аутентификации: хеширование, JWT, TOTP."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import settings

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)  # Argon2id
ISS, AUD = "securevault", "securevault-api"


# ---------- Хранение аутентификатора ----------
def _prehash(auth_key_b64: str) -> str:
    """Pepper: HMAC с ключом, которого нет в БД. Утечка только БД не даёт офлайн-перебор."""
    return base64.b64encode(hmac.new(settings.pepper, auth_key_b64.encode(), hashlib.sha256).digest()).decode()


def hash_auth_key(auth_key_b64: str) -> str:
    return _ph.hash(_prehash(auth_key_b64))


def verify_auth_key(stored_hash: str, auth_key_b64: str) -> bool:
    try:
        return _ph.verify(stored_hash, _prehash(auth_key_b64))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(h: str) -> bool:
    return _ph.check_needs_rehash(h)


DUMMY_HASH = _ph.hash("dummy")  # для выравнивания времени ответа при неизвестном email


def fake_salt(email: str) -> str:
    """Детерминированная «соль» для несуществующих email -> защита от перечисления пользователей."""
    return base64.b64encode(hmac.new(settings.fake_salt_key, email.encode(), hashlib.sha256).digest()[:16]).decode()


# ---------- Токены ----------
def create_access_token(user_id: str, sid: str) -> str:
    now = int(time.time())
    claims = {"iss": ISS, "aud": AUD, "sub": user_id, "sid": sid, "typ": "access",
              "iat": now, "exp": now + settings.access_ttl, "jti": secrets.token_hex(8)}
    return jwt.encode(claims, settings.jwt_key, algorithm="HS256")


def decode_access_token(token: str) -> Optional[dict]:
    try:  # algorithms зафиксированы -> атаки alg=none / подмена алгоритма невозможны
        c = jwt.decode(token, settings.jwt_key, algorithms=["HS256"], audience=AUD, issuer=ISS,
                       options={"require": ["exp", "iat", "sub", "sid", "typ"]})
    except jwt.PyJWTError:
        return None
    return c if c.get("typ") == "access" else None


def new_refresh_token() -> tuple:
    raw = secrets.token_urlsafe(48)  # 384 бита энтропии => быстрый SHA-256 достаточен
    return raw, sha256hex(raw)


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------- TOTP (RFC 6238, HMAC-SHA1, 30 c, 6 цифр) ----------
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp_code(secret_b32: str, t: Optional[float] = None, step: int = 30) -> str:
    counter = int((t if t is not None else time.time()) // step)
    h = hmac.new(base64.b32decode(secret_b32), struct.pack(">Q", counter), "sha1").digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


def verify_totp(secret_b32: str, code: str, last_step: int, window: int = 1) -> Optional[int]:
    """Возвращает использованный шаг или None. Шаг <= last_step отвергается (защита от replay)."""
    now_step = int(time.time() // 30)
    for s in range(now_step - window, now_step + window + 1):
        if s > last_step and hmac.compare_digest(totp_code(secret_b32, s * 30), code):
            return s
    return None
