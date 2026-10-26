"""Точка входа: безопасные заголовки, принудительный HTTPS, лимит тела, скрытие ошибок."""
import logging
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import logconf
from .config import settings
from .db import Base, engine
from .routes_auth import router as auth_router
from .routes_vault import router as vault_router

log = logging.getLogger("securevault")
http_log = logging.getLogger("securevault.http")
logconf.setup()
app = FastAPI(title="SecureVault", docs_url=None if settings.env == "prod" else "/docs",
              redoc_url=None, openapi_url=None if settings.env == "prod" else "/openapi.json")
Base.metadata.create_all(engine)  # в проде - миграции Alembic

SEC_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",       # секреты не оседают в кэшах браузера/прокси
    "Pragma": "no-cache",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    t0, ip = time.time(), (request.client.host if request.client else "-")
    resp = await _guarded(request, call_next)
    if request.url.path != "/health":
        http_log.info(logconf.http_line(time.strftime("%H:%M:%S"), request.method, request.url.path,
                                        resp.status_code, (time.time() - t0) * 1000, ip))
        body = getattr(request.state, "body", b"")
        if body:
            http_log.info(logconf.c(logconf.CYAN, "          body " + logconf.shape(body)))
    return resp


async def _guarded(request: Request, call_next):
    if settings.require_https and request.headers.get("x-forwarded-proto", request.url.scheme) != "https":
        return JSONResponse({"detail": "HTTPS required"}, status_code=400)
    cl = request.headers.get("content-length")
    if cl and (not cl.isdigit() or int(cl) > settings.max_body):
        return JSONResponse({"detail": "Payload too large"}, status_code=413)
    request.state.body = await request.body() if cl else b""
    resp = await call_next(request)
    resp.headers.update(SEC_HEADERS)
    if "server" in resp.headers:
        del resp.headers["server"]
    return resp


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error")  # детали только в лог, клиенту - ничего лишнего
    return JSONResponse({"detail": "Internal error"}, status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(vault_router)
