# SecureVault - защищённый онлайн-менеджер паролей (zero-knowledge)

Курсовой проект: «Компьютерная безопасность. Разработка защищённого онлайн-сервиса менеджера
паролей с безопасной передачей и хранением данных на сервере».

## 1. Запуск
```bash
pip install -r requirements.txt
python -m pytest -q                       # 33 теста, каждый проверяет защитный механизм
uvicorn app.main:app --reload             # dev; Swagger: /docs
python -m app.maintenance verify          # проверка целостности журнала аудита
python -m app.maintenance rotate          # ротация серверного KEK
```
Прод: `deploy/` (Docker + nginx с TLS 1.2/1.3), секреты по `.env.example`.

## 1a. Демонстрация в двух терминалах
```bash
# Терминал 1 - сервер: живой лог запросов и событий аудита (секретов в логе нет, только имена полей и размеры)
uvicorn app.main:app --no-access-log

# Терминал 2 - клиент (trace по умолчанию включён: видно, что уходит на сервер и что делается локально)
python -m client.cli
> register  ->  login  ->  add  ->  list  ->  show 1  ->  2fa  ->  audit
> attack brute | reuse | forge | idor      # атаки, реакцию сервера смотрите в терминале 1 (красные [AUDIT])

# Терминал 3 - что реально лежит в БД и цел ли журнал аудита
python -m app.maintenance dump
python -m app.maintenance verify
```
Что показать на защите: в `trace` в запросе только `auth_key` и шифртекст (пароль сайта и мастер-пароль не уходят);
в `dump` - `sealed`-blob и Argon2id-хеши без плейнтекста; после `attack reuse` - `refresh_reuse_detected` и убитая сессия;
после `attack brute` - `account_locked` и неотличимый ответ на верный пароль. Строка `[AUDIT]` печатается раньше строки
запроса, потому что событие пишется внутри обработчика, а строка запроса - после ответа. В dev-режиме секреты лежат в
`.dev_secrets.json` (чтобы БД переживала перезапуск); в проде - только из окружения/KMS.

## 2. Архитектура и модель доверия
```
 КЛИЕНТ (доверенная зона)                         СЕРВЕР (недоверенный по отношению к данным)
 мастер-пароль --Argon2id--> master_key
   master_key --HKDF--> enc_key ──шифрует──> vault_key (случайный)   ┐ wrapped_vault_key
   master_key --HKDF--> auth_key ───────────────────────────────────>│ Argon2id(HMAC(pepper, auth_key))
 запись --AES-256-GCM(vault_key, AAD=id)--> ciphertext ──TLS 1.3──>   │ AES-256-GCM(DEK) ; DEK под KEK
                                                                      ┘ (двойное шифрование)
```
Сервер никогда не получает мастер-пароль, `enc_key`, `vault_key` и открытые данные.
Утечка БД ⇒ атакующий имеет только Argon2id-хеши (с перцем) и шифртексты.

## 3. Реализованные механизмы безопасности

| # | Механизм | Угроза | Файл | Тест |
|---|----------|--------|------|------|
| 1 | Zero-knowledge, клиентское шифрование AES-256-GCM | Утечка БД, злонамеренный админ | `client/zk_client.py` | `test_roundtrip_and_server_never_sees_plaintext`, `test_server_never_receives_master_password` |
| 2 | Argon2id KDF на клиенте (m≥19 МиБ, t≥2) + HKDF-разделение ключей | Перебор мастер-пароля, радужные таблицы | `zk_client.derive`, `schemas.RegisterIn` | `test_weak_kdf_params_rejected` |
| 3 | Argon2id хеш `auth_key` на сервере + pepper (HMAC) | Офлайн-подбор при утечке БД | `security.py` | `test_pepper_...` |
| 4 | Конвертное шифрование at rest (DEK/KEK), AAD-привязка к user/record | Кража БД/бэкапов, подмена и перестановка blob'ов | `crypto_server.py` | `test_db_tamper_detected`, `test_ciphertext_swap_...` |
| 5 | Версионирование и ротация KEK без расшифровки данных | Компрометация ключа, требования комплаенса | `crypto_server.rewrap`, `maintenance.py` | `test_kek_rotation`, `test_rotate_all_db` |
| 6 | Разделение ключей через HKDF (jwt/audit/pepper/fake-salt) | Каскадная компрометация | `config.py` | - |
| 7 | JWT: HS256 зафиксирован, iss/aud/exp/typ, короткий TTL 10 мин | alg=none, подделка, replay | `security.py` | `test_unauthenticated_and_forged_tokens` |
| 8 | Refresh-ротация + **reuse detection**, хранение хеша токена, серверная отзываемость сессий | Кража токена | `routes_auth.refresh`, `deps.current_user` | `test_refresh_rotation_and_reuse_detection`, `test_logout_revokes_session` |
| 9 | Блокировка аккаунта (экспоненциальная) + rate limit (приложение и nginx) | Brute force, credential stuffing | `routes_auth.login`, `ratelimit.py` | `test_lockout_...`, `test_rate_limit_login` |
| 10 | Защита от перечисления пользователей: поддельная соль, dummy-хеш, одинаковые ответы | User enumeration, timing-атаки | `routes_auth.prelogin/login` | `test_wrong_password_and_unknown_user_same_response`, `test_prelogin_does_not_enumerate` |
| 11 | TOTP 2FA (RFC 6238), секрет шифруется KEK, anti-replay по шагу | Кража пароля | `security.py`, `routes_auth` | `test_totp_flow_and_replay_protection`, `test_totp_secret_encrypted_in_db` |
| 12 | Авторизация на уровне объекта (фильтр user_id), 404 вместо 403 | IDOR / BOLA (OWASP API1) | `routes_vault._own` | `test_idor_blocked` |
| 13 | Оптимистическая блокировка версий | Потерянные обновления, гонки | `routes_vault.update_item` | `test_optimistic_locking` |
| 14 | Строгая валидация (pydantic, `extra=forbid`, regex, лимиты), ORM | Инъекции, mass assignment, DoS | `schemas.py`, `db.py` | `test_input_validation`, `test_sql_injection_in_path` |
| 15 | Лимит размера тела и квота записей | DoS | `main.py`, `routes_vault` | `test_oversized_body_rejected` |
| 16 | Принудительный HTTPS, HSTS, TLS ≥1.2, только ECDHE (PFS) | MITM, downgrade, sniffing | `main.py`, `deploy/nginx.conf` | `test_https_enforced_in_prod` |
| 17 | Security-заголовки: CSP, nosniff, X-Frame-Options, `Cache-Control: no-store`, Referrer-Policy | XSS/clickjacking/утечка через кэш | `main.py` | `test_security_headers` |
| 18 | Tamper-evident аудит: HMAC-цепочка, без секретов в логах | Сокрытие следов, инсайдер | `audit.py` | `test_audit_chain_detects_tampering`, `test_audit_detects_deleted_record`, `test_no_secrets_in_audit` |
| 19 | Обработка ошибок без утечки деталей, отключение docs в проде | Information disclosure | `main.py` | - |
| 20 | Контейнер: non-root, read-only FS, `cap_drop ALL`, внутренняя сеть, секреты вне образа | Эскалация при RCE | `deploy/` | - |
| 21 | Генератор паролей на CSPRNG; проверка утечек HIBP по k-anonymity | Слабые/скомпрометированные пароли | `zk_client.py` | `test_generator`, `test_hibp_k_anonymity` |

## 4. Модель угроз (STRIDE, кратко)
- **Spoofing** - Argon2id+pepper, 2FA, короткие JWT, reuse detection.
- **Tampering** - AEAD (GCM) с AAD, оптимистическая блокировка, HMAC-цепочка аудита.
- **Repudiation** - неизменяемый аудит всех security-событий (вход, блокировка, reuse, нарушение целостности).
- **Information disclosure** - zero-knowledge, двойное шифрование, анти-энумерация, no-store, обезличенные ошибки.
- **DoS** - rate limit, лимиты размера, квоты, блокировка.
- **Elevation of privilege** - проверка владельца на каждом запросе, non-root контейнер.

Соответствие стандартам: OWASP ASVS (V2 аутентификация, V3 сессии, V4 контроль доступа, V6 криптография,
V7 логирование, V9 коммуникации), OWASP API Top 10 (API1, API2, API4, API8), NIST SP 800-63B / 800-132,
RFC 9106 (Argon2), RFC 6238 (TOTP), RFC 5869 (HKDF).
