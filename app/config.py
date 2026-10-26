"""Конфигурация и управление секретами.

Секреты берутся ТОЛЬКО из окружения (в проде - из Vault/KMS/Docker secrets).
Из одного APP_SECRET через HKDF выводятся независимые подключи (key separation):
компрометация одного назначения не раскрывает остальные.
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _hkdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def _dev_secrets() -> dict:
    """Dev: секреты в локальном файле, чтобы БД и аудит переживали перезапуск (не для прода!)."""
    path = os.getenv("DEV_SECRETS_FILE", ".dev_secrets.json")
    if os.path.exists(path):
        return json.load(open(path))
    d = {"kek": base64.b64encode(os.urandom(32)).decode(), "app": base64.b64encode(os.urandom(32)).decode()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    return d


class Settings:
    def __init__(self) -> None:
        self.env = os.getenv("APP_ENV", "dev")
        prod = self.env == "prod"
        self.db_url = os.getenv("DATABASE_URL", "sqlite:///./vault.db")
        self.require_https = prod

        # --- KEK (Key Encryption Keys) с версионированием для ротации ---
        raw = os.getenv("SERVER_KEKS")  # формат: "1:<b64>,2:<b64>"
        if raw:
            self.keks = {int(i): base64.b64decode(k) for i, k in (p.split(":", 1) for p in raw.split(","))}
            self.active_kek = int(os.getenv("ACTIVE_KEK_ID", max(self.keks)))
        elif prod:
            raise RuntimeError("SERVER_KEKS обязателен в production")
        elif self.env == "dev":
            self.keks, self.active_kek = {1: base64.b64decode(_dev_secrets()["kek"])}, 1
        else:
            self.keks, self.active_kek = {1: os.urandom(32)}, 1  # test: эфемерный
        if any(len(k) != 32 for k in self.keks.values()):
            raise RuntimeError("KEK должен быть 32 байта")

        # --- Главный секрет приложения -> подключи ---
        secret = os.getenv("APP_SECRET")
        if secret:
            sec = base64.b64decode(secret)
        elif prod:
            raise RuntimeError("APP_SECRET обязателен в production")
        elif self.env == "dev":
            sec = base64.b64decode(_dev_secrets()["app"])
        else:
            sec = os.urandom(32)
        if len(sec) < 32:
            raise RuntimeError("APP_SECRET должен быть >= 32 байт")
        self.jwt_key = _hkdf(sec, b"jwt-signing")
        self.audit_key = _hkdf(sec, b"audit-hmac")
        self.pepper = _hkdf(sec, b"auth-pepper")
        self.fake_salt_key = _hkdf(sec, b"fake-salt")

        # --- Политики ---
        self.access_ttl = 600            # 10 минут
        self.refresh_ttl = 14 * 86400    # 14 дней
        self.max_failed = 5              # порог блокировки
        self.base_lock = 900             # 15 минут, растёт экспоненциально
        self.max_body = 128 * 1024
        self.max_items = 5000
        self.min_kdf = {"time": 2, "mem": 19456, "par": 1}  # OWASP: Argon2id m=19MiB,t=2,p=1


settings = Settings()
