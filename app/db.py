"""Модели БД. Все запросы идут через ORM (параметризованные) -> защита от SQL-инъекций.
Время хранится как epoch-секунды."""
from typing import Optional

from sqlalchemy import Integer, LargeBinary, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import settings

engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False} if settings.db_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    kdf_salt: Mapped[str] = mapped_column(String(64))
    kdf_time: Mapped[int] = mapped_column(Integer)
    kdf_mem: Mapped[int] = mapped_column(Integer)
    kdf_par: Mapped[int] = mapped_column(Integer)
    auth_hash: Mapped[str] = mapped_column(String(255))          # Argon2id(HMAC(pepper, auth_key))
    wrapped_vault_key: Mapped[str] = mapped_column(String(256))  # зашифровано на клиенте
    totp_sealed: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)  # шифр. KEK
    totp_enabled: Mapped[int] = mapped_column(Integer, default=0)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[int] = mapped_column(Integer)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    family_id: Mapped[str] = mapped_column(String(36), index=True)  # = идентификатор сессии (sid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[int] = mapped_column(Integer)
    used: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[int] = mapped_column(Integer, default=0)


class VaultItem(Base):
    __tablename__ = "vault_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    sealed: Mapped[bytes] = mapped_column(LargeBinary)  # конверт: KEK(DEK) + DEK(client_ciphertext)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(Integer)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
