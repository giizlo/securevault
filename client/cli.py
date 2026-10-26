"""Интерактивный терминальный клиент SecureVault.
Запуск (из корня проекта):  python -m client.cli [--url http://127.0.0.1:8000] [--no-trace]
Режим trace показывает, что именно клиент отправляет на сервер и что получает в ответ."""
import argparse
import base64
import getpass
import hmac
import json
import os
import struct
import sys
import time

import httpx

from .zk_client import API, ZKClient, generate_password

NO = bool(os.getenv("NO_COLOR"))
c = lambda code, s: s if NO else f"\033[{code}m{s}\033[0m"  # noqa: E731

HELP = """Команды:
  register / login / logout / whoami     учётная запись
  add | list | show N | edit N | rm N    записи (N - номер из list)
  gen [длина]                            генератор паролей
  2fa                                    включить TOTP
  refresh                                ротация refresh-токена
  audit                                  мои события аудита (с сервера)
  trace on|off                           показ сетевого обмена и крипто-шагов
  attack reuse|brute|forge|idor          демонстрация атак (смотрите лог сервера!)
  help / quit"""


def short(v):
    if isinstance(v, str) and len(v) > 30:
        return f"{v[:22]}…[{len(v)}ch]"
    if isinstance(v, dict):
        return {k: short(x) for k, x in v.items()}
    if isinstance(v, list):
        return [short(x) for x in v[:3]] + (["…"] if len(v) > 3 else [])
    return v


class Traced:
    """Обёртка над httpx.Client: печатает каждый запрос/ответ (значения сокращены)."""
    def __init__(self, inner):
        self.inner, self.on = inner, True

    def _call(self, m, url, **kw):
        if self.on:
            print(c("36", f"  >> {m.upper()} {url}"))
            if kw.get("json") is not None:
                print(c("36", f"     body: {json.dumps(short(kw['json']), ensure_ascii=False)}"))
            if kw.get("headers", {}).get("Authorization"):
                print(c("36", f"     Authorization: {short(kw['headers']['Authorization'])}"))
        r = getattr(self.inner, m)(url, **kw)
        if self.on:
            try:
                txt = json.dumps(short(r.json()), ensure_ascii=False)
            except Exception:
                txt = r.text[:80]
            print(c("33", f"  << {r.status_code} {txt}"))
        return r

    post = lambda self, u, **k: self._call("post", u, **k)  # noqa: E731
    get = lambda self, u, **k: self._call("get", u, **k)  # noqa: E731
    put = lambda self, u, **k: self._call("put", u, **k)  # noqa: E731
    delete = lambda self, u, **k: self._call("delete", u, **k)  # noqa: E731


def totp_code(secret: str) -> str:
    h = hmac.new(base64.b32decode(secret), struct.pack(">Q", int(time.time() // 30)), "sha1").digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


class App:
    def __init__(self, url: str, trace: bool):
        self.http = Traced(httpx.Client(base_url=url, timeout=30))
        self.http.on = trace
        self.cl = None
        self.cache = []

    def say(self, msg):
        if self.http.on:
            print(c("35", f"  [client] {msg}"))

    def need_login(self):
        if not self.cl or not self.cl.vault_key:
            print(c("31", "Сначала войдите: login"))
            return False
        return True

    def ask_creds(self):
        return input("email: ").strip(), getpass.getpass("мастер-пароль: ")

    # ---- команды ----
    def register(self, _):
        email, pw = self.ask_creds()
        cl = ZKClient(self.http, email, pw); cl.say = self.say
        r = cl.register()
        print(c("32", "Регистрация отправлена") if r.status_code == 201 else c("31", f"Ошибка {r.status_code}"))

    def login(self, _):
        email, pw = self.ask_creds()
        cl = ZKClient(self.http, email, pw); cl.say = self.say
        r = cl.login()
        if r.status_code == 401 and r.json().get("detail") == "totp_required":
            r = cl.login(totp=input("код 2FA: ").strip())
        if r.status_code == 200:
            self.cl = cl
            print(c("32", f"Вход выполнен как {cl.email}. vault_key расшифрован ЛОКАЛЬНО"))
        else:
            print(c("31", f"Отказ: {r.status_code} {r.json().get('detail')}"))

    def logout(self, _):
        if self.need_login():
            self.cl.logout(); self.cl = None
            print("Сессия отозвана на сервере")

    def whoami(self, _):
        print(self.cl.email if self.cl else "не авторизован")

    def add(self, _):
        if not self.need_login():
            return
        title = input("название: ")
        user = input("логин: ")
        pw = getpass.getpass("пароль (Enter - сгенерировать): ") or generate_password(20)
        url = input("url: ")
        iid = self.cl.add_item({"title": title, "username": user, "password": pw, "url": url})
        print(c("32", f"Сохранено, id={iid[:8]}"))

    def list(self, _):
        if not self.need_login():
            return
        self.cache = self.cl.list_items()
        for n, it in enumerate(self.cache, 1):
            print(f"  {n:>2}. {it['title']:<20} {it['username']:<20} v{it['version']} id={it['id'][:8]}")
        if not self.cache:
            print("  (пусто)")

    def _pick(self, arg):
        if not self.need_login():
            return None
        if not self.cache:
            self.cache = self.cl.list_items()
        try:
            return self.cache[int(arg) - 1]
        except (ValueError, IndexError):
            print(c("31", "Укажите номер из list"))

    def show(self, arg):
        if it := self._pick(arg):
            print(json.dumps({k: v for k, v in it.items() if k != "version"}, ensure_ascii=False, indent=2))

    def edit(self, arg):
        if it := self._pick(arg):
            new = getpass.getpass("новый пароль (Enter - сгенерировать): ") or generate_password(20)
            data = {k: v for k, v in it.items() if k not in ("id", "version")} | {"password": new}
            r = self.cl.update_item(it["id"], data, it["version"])
            print(c("32", "Обновлено") if r.status_code == 200 else c("31", f"Ошибка {r.status_code}"))
            self.cache = []

    def rm(self, arg):
        if it := self._pick(arg):
            print(c("32", "Удалено") if self.cl.delete_item(it["id"]).status_code == 204 else c("31", "Ошибка"))
            self.cache = []

    def gen(self, arg):
        print(generate_password(int(arg) if arg.isdigit() else 20))

    def refresh(self, _):
        if self.need_login():
            r = self.cl.refresh()
            print(c("32", "Токены ротированы") if r.status_code == 200 else c("31", f"Ошибка {r.status_code}"))

    def audit(self, _):
        if self.need_login():
            for e in self.http.get(f"{API}/vault/audit", headers=self.cl._h()).json()[:15]:
                print(f"  {time.strftime('%H:%M:%S', time.localtime(e['ts']))}  {e['event']:<24} {e['ip']}")

    def twofa(self, _):
        if not self.need_login():
            return
        r = self.http.post(f"{API}/auth/2fa/setup", headers=self.cl._h())
        if r.status_code != 200:
            return print(c("31", "2FA уже включена"))
        secret = r.json()["secret"]
        print(f"Секрет для приложения-аутентификатора: {secret}")
        code = input("введите код (или 'auto' - вычислить локально для демо): ").strip()
        code = totp_code(secret) if code == "auto" else code
        r = self.http.post(f"{API}/auth/2fa/enable", json={"code": code}, headers=self.cl._h())
        print(c("32", "2FA включена") if r.status_code == 200 else c("31", "Неверный код"))

    def trace(self, arg):
        self.http.on = arg == "on"
        print("trace", "включён" if self.http.on else "выключен")

    # ---- демонстрации атак ----
    def attack(self, arg):
        quiet = Traced(self.http.inner); quiet.on = self.http.on
        if arg == "forge":
            import jwt
            tok = jwt.encode({"sub": "x"}, "wrong-key", algorithm="HS256")
            r = quiet.get(f"{API}/vault/items", headers={"Authorization": f"Bearer {tok}"})
            print(f"Поддельный JWT -> {r.status_code} (ожидается 401)")
        elif arg == "reuse":
            if not self.need_login():
                return
            old = self.cl.refresh_token
            print("1) легитимная ротация:", self.cl.refresh().status_code)
            r = quiet.post(f"{API}/auth/refresh", json={"refresh_token": old})
            print(f"2) повтор УКРАДЕННОГО старого токена -> {r.status_code}; сессия убита целиком")
            print("3) токен жертвы теперь тоже мёртв:", quiet.post(f"{API}/auth/refresh", json={"refresh_token": self.cl.refresh_token}).status_code)
            self.cl = None
            print(c("33", "Войдите заново (login)"))
        elif arg == "brute":
            email = f"victim{os.urandom(2).hex()}@demo.local"
            ZKClient(quiet, email, "RealPassword-123").register()
            for i in range(1, 7):
                r = ZKClient(quiet, email, f"guess{i}").login()
                print(f"  попытка {i}: {r.status_code}")
            r = ZKClient(quiet, email, "RealPassword-123").login()
            print(f"  ВЕРНЫЙ пароль после блокировки -> {r.status_code} (аккаунт заблокирован; ответ неотличим от неверного пароля)")
        elif arg == "idor":
            if not self.need_login() or not (self.cache or self.cl.list_items()):
                return print("Нужны вход и хотя бы одна запись")
            target = (self.cache or self.cl.list_items())[0]["id"]
            mal = ZKClient(quiet, f"mallory{os.urandom(2).hex()}@demo.local", "Mallory-pass-123")
            mal.register(); mal.login()
            r = quiet.get(f"{API}/vault/items/{target}", headers=mal._h())
            print(f"Чужой пользователь читает вашу запись -> {r.status_code} (404, существование записи не раскрывается)")
        else:
            print("attack reuse|brute|forge|idor")

    def run(self):
        print(c("1", "SecureVault CLI") + "  (help - список команд)")
        cmds = {"register": self.register, "login": self.login, "logout": self.logout, "whoami": self.whoami,
                "add": self.add, "list": self.list, "show": self.show, "edit": self.edit, "rm": self.rm,
                "gen": self.gen, "2fa": self.twofa, "refresh": self.refresh, "audit": self.audit,
                "trace": self.trace, "attack": self.attack}
        while True:
            try:
                line = input(c("1", f"[{self.cl.email if self.cl else 'гость'}]> ")).strip()
            except (EOFError, KeyboardInterrupt):
                print(); return
            cmd, _, arg = line.partition(" ")
            if cmd in ("quit", "exit"):
                return
            if cmd in ("help", "?", ""):
                print(HELP if cmd != "" else "", end="\n" if cmd != "" else "")
                continue
            if cmd not in cmds:
                print(c("31", "неизвестная команда, help"))
                continue
            try:
                cmds[cmd](arg.strip())
            except httpx.ConnectError:
                print(c("31", "Сервер недоступен"))
            except Exception as e:  # noqa: BLE001
                print(c("31", f"Ошибка: {e}"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--no-trace", action="store_true")
    a = ap.parse_args()
    App(a.url, not a.no_trace).run()
