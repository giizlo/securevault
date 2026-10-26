"""Серверное шифрование «на покое» (encryption at rest): конвертное шифрование.

Для каждой записи генерируется случайный DEK (AES-256-GCM шифрует данные),
DEK шифруется KEK (тоже AES-256-GCM). Формат контейнера:
    kek_id(2B) | len(wrapped)(2B) | wrapped_dek | nonce+ciphertext
AAD привязывает шифртекст к владельцу и записи -> нельзя «пересадить» blob
другому пользователю/записи (защита от подмены на уровне БД).

Данные уже зашифрованы клиентом => на сервере получается ДВОЙНОЕ шифрование.
Ротация KEK: rewrap() перешифровывает только DEK, данные не трогаются.
"""
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


def _enc(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)  # 96-бит случайный nonce; новый DEK на запись => коллизии неважны
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def _dec(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)  # InvalidTag при любой подмене


def seal(plaintext: bytes, aad: bytes) -> bytes:
    kid = settings.active_kek
    dek = AESGCM.generate_key(256)
    wrapped = _enc(settings.keks[kid], dek, b"dek|" + aad)
    return struct.pack(">HH", kid, len(wrapped)) + wrapped + _enc(dek, plaintext, aad)


def _split(sealed: bytes):
    kid, wlen = struct.unpack(">HH", sealed[:4])
    return kid, sealed[4:4 + wlen], sealed[4 + wlen:]


def unseal(sealed: bytes, aad: bytes) -> bytes:
    kid, wrapped, blob = _split(sealed)
    dek = _dec(settings.keks[kid], wrapped, b"dek|" + aad)
    return _dec(dek, blob, aad)


def rewrap(sealed: bytes, aad: bytes) -> bytes:
    """Ротация KEK: расшифровать DEK старым ключом, зашифровать активным."""
    kid, wrapped, blob = _split(sealed)
    if kid == settings.active_kek:
        return sealed
    dek = _dec(settings.keks[kid], wrapped, b"dek|" + aad)
    new = _enc(settings.keks[settings.active_kek], dek, b"dek|" + aad)
    return struct.pack(">HH", settings.active_kek, len(new)) + new + blob
