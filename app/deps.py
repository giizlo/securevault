"""Зависимости: сессия БД, IP клиента, аутентификация по Bearer-токену."""
import time

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import RefreshToken, SessionLocal, User
from .security import decode_access_token

_bearer = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request) -> str:
    # За прокси запускать uvicorn с --proxy-headers --forwarded-allow-ips=<ip nginx>
    return request.client.host if request.client else "-"


def current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer),
                 db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if not creds:
        raise unauthorized
    claims = decode_access_token(creds.credentials)
    if not claims:
        raise unauthorized
    # Серверная отзываемость: сессия жива, только если в семействе есть непросроченный неотозванный refresh
    alive = db.scalar(select(RefreshToken.id).where(
        RefreshToken.family_id == claims["sid"], RefreshToken.user_id == claims["sub"],
        RefreshToken.revoked == 0, RefreshToken.expires_at > int(time.time())).limit(1))
    user = db.get(User, claims["sub"]) if alive else None
    if not user:
        raise unauthorized
    user._sid = claims["sid"]  # type: ignore[attr-defined]
    return user
