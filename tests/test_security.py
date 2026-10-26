import base64
import time

import jwt
import pytest
from sqlalchemy import select, text

from app import audit
from app.config import settings
from app.crypto_server import rewrap, seal, unseal
from app.db import RefreshToken, User, VaultItem
from app.maintenance import rotate_all
from app.security import totp_code
from client.zk_client import ZKClient, generate_password, pwned_count

SECRET_PW = "SuperSecretSitePassword!42"


# ---------- Zero-knowledge и шифрование ----------
def test_roundtrip_and_server_never_sees_plaintext(alice, db):
    iid = alice.add_item({"site": "bank.com", "password": SECRET_PW})
    assert alice.get_item(iid)["password"] == SECRET_PW
    raw = db.scalar(select(VaultItem.sealed).where(VaultItem.id == iid))
    assert SECRET_PW.encode() not in raw and b"bank.com" not in raw          # шифртекст
    assert alice.password.encode() not in db.scalar(select(User.auth_hash)).encode()  # мастер-пароль не хранится


def test_server_never_receives_master_password(http, monkeypatch):
    seen = []
    orig = http.post
    monkeypatch.setattr(http, "post", lambda *a, **k: (seen.append(str(k.get("json"))), orig(*a, **k))[1])
    c = ZKClient(http, "z@example.com", "MasterPassw0rd-unique")
    c.register(); c.login()
    assert not any("MasterPassw0rd-unique" in s for s in seen)


def test_db_tamper_detected(alice, db):
    iid = alice.add_item({"p": "x"})
    it = db.get(VaultItem, iid)
    b = bytearray(it.sealed); b[-1] ^= 1; it.sealed = bytes(b); db.commit()
    assert alice.http.get(f"/api/v1/vault/items/{iid}", headers=alice._h()).status_code == 500


def test_ciphertext_swap_between_records_detected(alice, db):
    a, b = alice.add_item({"p": "A"}), alice.add_item({"p": "B"})
    ia, ib = db.get(VaultItem, a), db.get(VaultItem, b)
    ib.sealed = ia.sealed; db.commit()  # AAD привязан к id записи
    assert alice.http.get(f"/api/v1/vault/items/{b}", headers=alice._h()).status_code == 500


def test_kek_rotation(monkeypatch):
    old = dict(settings.keks)
    aad = b"item|u|i"
    s1 = seal(b"data", aad)
    monkeypatch.setattr(settings, "keks", {**old, 2: b"\x02" * 32})
    monkeypatch.setattr(settings, "active_kek", 2)
    s2 = rewrap(s1, aad)
    assert s2 != s1 and unseal(s2, aad) == b"data"
    monkeypatch.setattr(settings, "keks", {2: b"\x02" * 32})  # старый KEK уничтожен
    assert unseal(s2, aad) == b"data"


def test_rotate_all_db(alice, db, monkeypatch):
    iid = alice.add_item({"p": 1})
    monkeypatch.setattr(settings, "keks", {**settings.keks, 9: b"\x09" * 32})
    monkeypatch.setattr(settings, "active_kek", 9)
    assert rotate_all(db) >= 1
    assert alice.get_item(iid) == {"p": 1}


# ---------- Аутентификация ----------
def test_wrong_password_and_unknown_user_same_response(http, alice):
    bad = ZKClient(http, "alice@example.com", "wrong"); r1 = bad.login()
    ghost = ZKClient(http, "ghost@example.com", "whatever"); r2 = ghost.login()
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()


def test_prelogin_does_not_enumerate(http, alice):
    a = http.post("/api/v1/auth/prelogin", json={"email": "alice@example.com"}).json()
    g = http.post("/api/v1/auth/prelogin", json={"email": "ghost@example.com"}).json()
    assert a.keys() == g.keys()
    g2 = http.post("/api/v1/auth/prelogin", json={"email": "ghost@example.com"}).json()
    assert g == g2  # подделка детерминирована


def test_duplicate_registration_not_revealed(http, alice):
    assert ZKClient(http, "alice@example.com", "other").register().status_code == 201


def test_lockout_after_failures(http, alice):
    bad = ZKClient(http, "alice@example.com", "nope")
    for _ in range(settings.max_failed):
        assert bad.login().status_code == 401
    assert alice.login().status_code == 401  # верный пароль, но аккаунт заблокирован


def test_pepper_changes_stored_hash_dependency(db, alice):
    from app.security import _prehash
    assert _prehash("AAAA") != "AAAA"


# ---------- Токены ----------
def test_unauthenticated_and_forged_tokens(http, alice):
    assert http.get("/api/v1/vault/items").status_code == 401
    forged = jwt.encode({"sub": "x", "sid": "y", "typ": "access", "iss": "securevault",
                         "aud": "securevault-api", "iat": 1, "exp": int(time.time()) + 999}, "attacker-key", "HS256")
    assert http.get("/api/v1/vault/items", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_tok = jwt.encode({"sub": "x"}, None, algorithm="none")
    assert http.get("/api/v1/vault/items", headers={"Authorization": f"Bearer {none_tok}"}).status_code == 401


def test_refresh_rotation_and_reuse_detection(http, alice, db):
    r1 = alice.refresh_token
    r = http.post("/api/v1/auth/refresh", json={"refresh_token": r1}); assert r.status_code == 200
    r2 = r.json()["refresh_token"]
    assert http.post("/api/v1/auth/refresh", json={"refresh_token": r1}).status_code == 401  # повтор => кража
    assert http.post("/api/v1/auth/refresh", json={"refresh_token": r2}).status_code == 401  # семейство убито
    assert alice.http.get("/api/v1/vault/items", headers=alice._h()).status_code == 401      # access тоже мёртв
    assert "refresh_reuse_detected" in [a.event for a in db.scalars(select(audit.AuditLog))]


def test_logout_revokes_session(http, alice):
    assert http.post("/api/v1/auth/logout", headers=alice._h()).status_code == 200
    assert http.get("/api/v1/vault/items", headers=alice._h()).status_code == 401


def test_refresh_token_stored_hashed(alice, db):
    assert alice.refresh_token not in [t.token_hash for t in db.scalars(select(RefreshToken))]


# ---------- 2FA ----------
def test_totp_flow_and_replay_protection(http, alice):
    setup = http.post("/api/v1/auth/2fa/setup", headers=alice._h()).json()
    secret = setup["secret"]
    assert http.post("/api/v1/auth/2fa/enable", json={"code": "000000"}, headers=alice._h()).status_code == 400
    assert http.post("/api/v1/auth/2fa/enable", json={"code": totp_code(secret)}, headers=alice._h()).status_code == 200
    c = ZKClient(http, "alice@example.com", alice.password)
    r = c.login(); assert r.status_code == 401 and r.json()["detail"] == "totp_required"
    assert c.login(totp=totp_code(secret)).status_code == 401           # тот же шаг => replay отвергнут
    assert c.login(totp=totp_code(secret, time.time() + 30)).status_code == 200


def test_totp_secret_encrypted_in_db(http, alice, db):
    secret = http.post("/api/v1/auth/2fa/setup", headers=alice._h()).json()["secret"]
    assert secret.encode() not in db.scalar(select(User.totp_sealed))


# ---------- Авторизация и валидация ----------
def test_idor_blocked(http, alice):
    iid = alice.add_item({"p": "secret"})
    bob = ZKClient(http, "bob@example.com", "bob-password-long"); bob.register(); bob.login()
    assert http.get(f"/api/v1/vault/items/{iid}", headers=bob._h()).status_code == 404
    assert http.delete(f"/api/v1/vault/items/{iid}", headers=bob._h()).status_code == 404
    assert bob.http.get("/api/v1/vault/items", headers=bob._h()).json() == []


def test_optimistic_locking(alice):
    iid = alice.add_item({"v": 1})
    assert alice.update_item(iid, {"v": 2}, 1).status_code == 200
    assert alice.update_item(iid, {"v": 3}, 1).status_code == 409


@pytest.mark.parametrize("payload", [
    {"email": "not-an-email"},
    {"email": "a@b.co", "extra": 1},
    {"email": "' OR 1=1 --"},
])
def test_input_validation(http, payload):
    assert http.post("/api/v1/auth/prelogin", json=payload).status_code == 422


def test_weak_kdf_params_rejected(http):
    c = ZKClient(http, "w@example.com", "pw")
    r = http.post("/api/v1/auth/register", json={
        "email": "w@example.com", "auth_key": base64.b64encode(b"k" * 32).decode(),
        "kdf_salt": base64.b64encode(b"s" * 16).decode(), "kdf_time": 1, "kdf_mem": 8, "kdf_par": 1,
        "wrapped_vault_key": base64.b64encode(b"x" * 48).decode()})
    assert r.status_code == 422


def test_sql_injection_in_path(alice):
    r = alice.http.get("/api/v1/vault/items/1' OR '1'='1", headers=alice._h())
    assert r.status_code == 404


def test_oversized_body_rejected(http, alice):
    r = http.post("/api/v1/vault/items", content=b"x" * (settings.max_body + 1), headers=alice._h())
    assert r.status_code == 413


# ---------- Транспорт, заголовки, rate limit ----------
def test_security_headers(http):
    h = http.get("/health").headers
    for k in ["strict-transport-security", "x-content-type-options", "content-security-policy", "cache-control"]:
        assert k in h
    assert h["cache-control"] == "no-store"


def test_rate_limit_login(http):
    codes = [http.post("/api/v1/auth/login", json={"email": "a@b.co", "auth_key": base64.b64encode(b"k" * 32).decode()}).status_code
             for _ in range(12)]
    assert 429 in codes


def test_https_enforced_in_prod(http, monkeypatch):
    monkeypatch.setattr(settings, "require_https", True)
    assert http.get("/health", headers={"x-forwarded-proto": "http"}).status_code == 400
    assert http.get("/health", headers={"x-forwarded-proto": "https"}).status_code == 200


# ---------- Аудит ----------
def test_audit_chain_detects_tampering(alice, db):
    alice.add_item({"p": 1})
    assert audit.verify_chain(db) is None
    db.execute(text("UPDATE audit_log SET event='nothing_happened' WHERE id=2")); db.commit()
    assert audit.verify_chain(db) == 2


def test_audit_detects_deleted_record(alice, db):
    alice.add_item({"p": 1})
    db.execute(text("DELETE FROM audit_log WHERE id=2")); db.commit()
    assert audit.verify_chain(db) is not None


def test_no_secrets_in_audit(alice, db):
    alice.add_item({"p": SECRET_PW})
    dump = " ".join(f"{r.event}{r.detail}" for r in db.scalars(select(audit.AuditLog)))
    assert SECRET_PW not in dump and alice.password not in dump


# ---------- Клиентские утилиты ----------
def test_generator():
    pw = generate_password(24)
    assert len(pw) == 24 and pw != generate_password(24)


def test_hibp_k_anonymity():
    import hashlib
    sha = hashlib.sha1(b"password").hexdigest().upper()
    sent = []
    def fake(prefix):
        sent.append(prefix)
        return f"{sha[5:]}:9999\nAAAAA:1"
    assert pwned_count("password", fake) == 9999
    assert sent == [sha[:5]] and len(sent[0]) == 5
