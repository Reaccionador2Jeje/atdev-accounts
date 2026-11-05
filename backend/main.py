from __future__ import annotations

import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import BASE_DIR, Settings
from .db import connect, init_db
from .oauth_utils import SUPPORTED_SCOPES
from .routers import account, admin, apikeys, auth, oauth
from .security import hash_client_secret, iso, load_or_create_private_key, utcnow

FRONTEND_FILES = {
    "index.html": "text/html; charset=utf-8",
    "account.html": "text/html; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "account.js": "application/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def _seed_client(conn, seed: dict) -> None:
    client_id = str(seed.get("client_id", "")).strip()
    raw_redirects = seed.get("redirect_uris") or []
    raw_scopes = seed.get("scopes") or SUPPORTED_SCOPES
    if not isinstance(raw_redirects, (list, tuple)):
        return
    if not isinstance(raw_scopes, (list, tuple)):
        return
    redirect_uris = [str(uri).strip() for uri in raw_redirects if str(uri).strip()]
    if not client_id or not redirect_uris:
        return
    scopes = [
        str(scope) for scope in raw_scopes if str(scope) in SUPPORTED_SCOPES
    ]
    if not scopes:
        return
    existing = conn.execute(
        "SELECT 1 FROM oauth_clients WHERE client_id = ?", (client_id,)
    ).fetchone()
    if existing:
        return
    secret = str(seed.get("client_secret") or "")
    is_public = bool(seed.get("public", not secret))
    if not is_public and len(secret) < 16:
        return
    conn.execute(
        """
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, name, redirect_uris, scopes,
             is_confidential, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            None if is_public else hash_client_secret(secret or ""),
            str(seed.get("name") or client_id),
            json.dumps(list(dict.fromkeys(redirect_uris))),
            " ".join(dict.fromkeys(scopes)),
            0 if is_public else 1,
            iso(utcnow()),
        ),
    )


def _seed_clients(settings: Settings) -> None:
    seeds: list[dict] = []
    if settings.default_client_redirect_uris:
        seeds.append(
            {
                "client_id": settings.default_client_id,
                "name": settings.default_client_name,
                "redirect_uris": list(settings.default_client_redirect_uris),
                "scopes": list(settings.default_client_scopes),
                "public": not settings.default_client_secret,
                "client_secret": settings.default_client_secret,
            }
        )
    seeds.extend(settings.seed_clients)
    if not seeds:
        return
    conn = connect(settings.db_path)
    try:
        for seed in seeds:
            _seed_client(conn, seed)
        conn.commit()
    finally:
        conn.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        resolved = settings or Settings.from_env()
        resolved.data_dir.mkdir(parents=True, exist_ok=True)
        init_db(resolved.db_path)
        app.state.settings = resolved
        app.state.private_key = load_or_create_private_key(resolved.signing_key_path)
        _seed_clients(resolved)
        yield

    app = FastAPI(
        title="AtDev Accounts",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list((settings or Settings.from_env()).allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Admin-Token"],
    )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next) -> Response:
        current: Settings = request.app.state.settings
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") not in current.allowed_origins:
                return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)

        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers.setdefault("Content-Security-Policy", CSP)
        if current.secure_cookies:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    app.include_router(auth.router)
    app.include_router(account.router)
    app.include_router(apikeys.router)
    app.include_router(admin.router)
    app.include_router(oauth.router)

    assets_dir = BASE_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> FileResponse:
        return FileResponse(BASE_DIR / "assets" / "logo.svg")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(BASE_DIR / "index.html")

    @app.get("/{filename}", include_in_schema=False)
    def frontend(filename: str) -> FileResponse:
        media_type = FRONTEND_FILES.get(filename)
        path = BASE_DIR / filename
        if media_type is None or not path.is_file():
            return JSONResponse({"detail": "Not found"}, status_code=404)
        return FileResponse(path, media_type=media_type)

    return app


app = create_app()
