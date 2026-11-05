from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _csv(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _clients(name: str) -> tuple[dict[str, Any], ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON") from exc
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a JSON array")
    return tuple(item for item in value if isinstance(item, dict))


@dataclass(frozen=True)
class Settings:
    app_name: str
    app_origin: str
    issuer: str
    data_dir: Path
    db_path: Path
    signing_key_path: Path
    session_cookie: str
    session_ttl_seconds: int
    remember_ttl_seconds: int
    secure_cookies: bool
    trust_proxy: bool
    allow_registration: bool
    admin_token: str
    access_token_ttl_seconds: int
    id_token_ttl_seconds: int
    refresh_token_ttl_seconds: int
    auth_code_ttl_seconds: int
    default_client_id: str
    default_client_secret: str
    default_client_name: str
    default_client_redirect_uris: tuple[str, ...]
    default_client_scopes: tuple[str, ...]
    seed_clients: tuple[dict[str, Any], ...]
    allowed_origins: tuple[str, ...]

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data"))).expanduser()
        app_origin = (
            os.environ.get("APP_ORIGIN")
            or os.environ.get("RENDER_EXTERNAL_URL")
            or "http://localhost:8000"
        ).rstrip("/")
        issuer = os.environ.get("ISSUER", app_origin).rstrip("/")
        secure_default = app_origin.startswith("https://")

        extra_origins = _csv("ALLOWED_ORIGINS")
        allowed_origins = tuple(
            dict.fromkeys(origin.rstrip("/") for origin in (app_origin, *extra_origins))
        )

        default_scopes = _csv("DEFAULT_CLIENT_SCOPES") or (
            "openid",
            "profile",
            "email",
            "offline_access",
        )
        default_redirects = _csv("DEFAULT_CLIENT_REDIRECT_URIS")

        return cls(
            app_name=os.environ.get("APP_NAME", "AtDev Accounts"),
            app_origin=app_origin,
            issuer=issuer,
            data_dir=data_dir,
            db_path=data_dir / "atdev.db",
            signing_key_path=data_dir / "keys" / "oidc-private.pem",
            session_cookie=os.environ.get("SESSION_COOKIE", "atdev_session"),
            session_ttl_seconds=_int("SESSION_TTL_DAYS", 14) * 86400,
            remember_ttl_seconds=_int("REMEMBER_TTL_DAYS", 30) * 86400,
            secure_cookies=_bool("SECURE_COOKIES", secure_default),
            trust_proxy=_bool("TRUST_PROXY", False),
            allow_registration=_bool("ALLOW_REGISTRATION", True),
            admin_token=os.environ.get("ADMIN_TOKEN", ""),
            access_token_ttl_seconds=_int("ACCESS_TOKEN_TTL_MINUTES", 60) * 60,
            id_token_ttl_seconds=_int("ID_TOKEN_TTL_MINUTES", 60) * 60,
            refresh_token_ttl_seconds=_int("REFRESH_TOKEN_TTL_DAYS", 30) * 86400,
            auth_code_ttl_seconds=_int("AUTH_CODE_TTL_MINUTES", 10) * 60,
            default_client_id=os.environ.get("DEFAULT_CLIENT_ID", "openweb-linux"),
            default_client_secret=os.environ.get("DEFAULT_CLIENT_SECRET", ""),
            default_client_name=os.environ.get("DEFAULT_CLIENT_NAME", "OpenWeb Linux"),
            default_client_redirect_uris=default_redirects,
            default_client_scopes=default_scopes,
            seed_clients=_clients("SEED_CLIENTS"),
            allowed_origins=allowed_origins,
        )
