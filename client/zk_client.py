"""Референсный zero-knowledge клиент. Вся криптография пользовательских данных - ЗДЕСЬ.
Мастер-пароль и vault_key никогда не покидают клиента.

master_password --Argon2id(salt)--> master_key --HKDF--> enc_key  (шифрует vault_key)
                                                    `--> auth_key (уходит на сервер; из него
                                                         нельзя получить enc_key)
vault_key (случайный 256 бит) шифрует каждую запись AES-256-GCM, AAD = id записи.
Смена мастер-пароля = перешифровать только vault_key, а не все записи."""
import base64
import hashlib
import json
import os
import secrets
import string
import uuid
from typing import Callable, Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

b64e = lambda b: base64.b64encode(b).decode()  # noqa: E731
b64d = base64.b64decode
API = "/api/v1"


def derive(password: str, salt: bytes, t: int, m: int, p: int) -> tuple:
    mk = hash_secret_raw(password.encode(), salt, t, m, p, 32, Type.ID)
    hk = lambda info: HKDF(hashes.SHA256(), 32, None, info).derive(mk)  # noqa: E731
    return hk(b"securevault/enc"), hk(b"securevault/auth")


def encrypt_blob(key: bytes, data: bytes, aad: bytes) -> bytes:
    n = os.urandom(12)
    return n + AESGCM(key).encrypt(n, data, aad)


def decrypt_blob(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


class ZKClient:
    def __init__(self, http, email: str, password: str):
        self.http, self.email, self.password = http, email.lower(), password
        self.vault_key: Optional[bytes] = None
        self.access = self.refresh_token = ""
        self.say = lambda msg: None  # хук трассировки для CLI

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self.access}"}

    def register(self):
        salt, (t, m, p) = os.urandom(16), (2, 19456, 1)
        enc_key, auth_key = derive(self.password, salt, t, m, p)
        vault_key = AESGCM.generate_key(256)
        self.say("Argon2id(пароль, соль) -> master_key; HKDF -> enc_key (локально) и auth_key (на сервер)")
        self.say("vault_key = 32 случайных байта; wrapped = AES-GCM(enc_key, vault_key). Пароль на сервер НЕ уходит")
        return self.http.post(f"{API}/auth/register", json={
            "email": self.email, "auth_key": b64e(auth_key), "kdf_salt": b64e(salt),
            "kdf_time": t, "kdf_mem": m, "kdf_par": p,
            "wrapped_vault_key": b64e(encrypt_blob(enc_key, vault_key, b"vault-key"))})

    def login(self, totp: Optional[str] = None):
        pre = self.http.post(f"{API}/auth/prelogin", json={"email": self.email}).json()
        enc_key, auth_key = derive(self.password, b64d(pre["kdf_salt"]), pre["time_cost"],
                                   pre["memory_cost"], pre["parallelism"])
        self.say("Argon2id по соли/параметрам сервера -> auth_key; enc_key остаётся на клиенте")
        body = {"email": self.email, "auth_key": b64e(auth_key)}
        if totp:
            body["totp"] = totp
        r = self.http.post(f"{API}/auth/login", json=body)
        if r.status_code == 200:
            d = r.json()
            self.access, self.refresh_token = d["access_token"], d["refresh_token"]
            self.vault_key = decrypt_blob(enc_key, b64d(d["wrapped_vault_key"]), b"vault-key")
        return r

    def add_item(self, data: dict) -> str:
        iid = str(uuid.uuid4())
        ct = encrypt_blob(self.vault_key, json.dumps(data).encode(), iid.encode())
        self.say(f"AES-256-GCM(vault_key, aad=id) -> {len(ct)} байт шифртекста; открытых данных в запросе нет")
        r = self.http.post(f"{API}/vault/items", json={"id": iid, "ciphertext": b64e(ct)}, headers=self._h())
        assert r.status_code == 201, r.text
        return iid

    def get_item(self, iid: str) -> dict:
        r = self.http.get(f"{API}/vault/items/{iid}", headers=self._h())
        r.raise_for_status()
        return json.loads(decrypt_blob(self.vault_key, b64d(r.json()["ciphertext"]), iid.encode()))

    def update_item(self, iid: str, data: dict, version: int):
        ct = encrypt_blob(self.vault_key, json.dumps(data).encode(), iid.encode())
        return self.http.put(f"{API}/vault/items/{iid}", json={"ciphertext": b64e(ct), "version": version},
                             headers=self._h())

    def list_items(self) -> list:
        r = self.http.get(f"{API}/vault/items", headers=self._h())
        r.raise_for_status()
        out = []
        for it in r.json():
            d = json.loads(decrypt_blob(self.vault_key, b64d(it["ciphertext"]), it["id"].encode()))
            out.append({"id": it["id"], "version": it["version"], **d})
        return out

    def delete_item(self, iid: str):
        return self.http.delete(f"{API}/vault/items/{iid}", headers=self._h())

    def refresh(self):
        r = self.http.post(f"{API}/auth/refresh", json={"refresh_token": self.refresh_token})
        if r.status_code == 200:
            self.access, self.refresh_token = r.json()["access_token"], r.json()["refresh_token"]
        return r

    def logout(self):
        return self.http.post(f"{API}/auth/logout", headers=self._h())


# ---------- Генератор паролей (CSPRNG) ----------
def generate_password(length: int = 20, symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits + ("!@#$%^&*()-_=+[]{}" if symbols else "")
    while True:  # гарантируем присутствие всех классов символов
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and (not symbols or any(c in "!@#$%^&*()-_=+[]{}" for c in pw))):
            return pw


# ---------- Проверка утечек по k-anonymity (HIBP Pwned Passwords) ----------
def pwned_count(password: str, fetch_range: Callable[[str], str]) -> int:
    """На сторону отправляются только первые 5 символов SHA-1; полный хеш и пароль не раскрываются.
    fetch_range(prefix) -> текст 'SUFFIX:COUNT' построчно (например, GET api.pwnedpasswords.com/range/<prefix>)."""
    sha = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324 (требование протокола HIBP)
    for line in fetch_range(sha[:5]).splitlines():
        suffix, _, cnt = line.partition(":")
        if suffix.strip() == sha[5:]:
            return int(cnt)
    return 0
