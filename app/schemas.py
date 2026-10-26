"""Строгая валидация входных данных (allow-list, лимиты длины, точные форматы)."""
import base64
import binascii
from typing import Annotated, Optional

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from .config import settings

UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
EMAIL_RE = r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,}$"


def _b64(exact: Optional[int] = None, max_bytes: int = 1024):
    def check(v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("invalid base64")
        if (exact and len(raw) != exact) or len(raw) > max_bytes:
            raise ValueError("invalid length")
        return v
    return AfterValidator(check)


Key32 = Annotated[str, Field(max_length=64), _b64(exact=32)]
Salt16 = Annotated[str, Field(max_length=32), _b64(exact=16)]
Blob = Annotated[str, Field(max_length=100_000), _b64(max_bytes=64 * 1024)]
Email = Annotated[str, Field(pattern=EMAIL_RE, max_length=254)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # лишние поля -> 422 (защита от mass assignment)


class PreloginIn(Strict):
    email: Email


class RegisterIn(Strict):
    email: Email
    auth_key: Key32
    kdf_salt: Salt16
    kdf_time: int = Field(ge=settings.min_kdf["time"], le=10)
    kdf_mem: int = Field(ge=settings.min_kdf["mem"], le=1_048_576)
    kdf_par: int = Field(ge=settings.min_kdf["par"], le=16)
    wrapped_vault_key: Annotated[str, Field(max_length=256), _b64(max_bytes=128)]


class LoginIn(Strict):
    email: Email
    auth_key: Key32
    totp: Optional[str] = Field(default=None, pattern=r"^\d{6}$")


class RefreshIn(Strict):
    refresh_token: str = Field(min_length=20, max_length=128)


class TotpEnableIn(Strict):
    code: str = Field(pattern=r"^\d{6}$")


class ItemCreate(Strict):
    id: str = Field(pattern=UUID_RE)
    ciphertext: Blob


class ItemUpdate(Strict):
    ciphertext: Blob
    version: int = Field(ge=1)
