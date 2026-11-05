from __future__ import annotations

import hmac
import sqlite3
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, Response, status

from .config import Settings
from .db import get_db
from .security import iso, new_token, token_digest, utcnow, decode_token, future

DB = Annotated[sqlite3.Connection, Depends(get_db)]


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def session_user(
    request: Request,
    db: DB,
    settings: Annotated[Settings, Depends(get_settings)],
    *,
    touch: bool = True,
) -> sqlite3.Row | None:
    token = request.cookies.get(settings.session_cookie)
    if not token:
        return None
    row = db.execute(
        """
        SELECT u.*, s.id AS session_id, s.expires_at AS session_expires_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
          AND s.revoked_at IS NULL
          AND s.expires_at > ?
        """,
        (token_digest(token), iso(utcnow())),
    ).fetchone()
    if row is None:
        return None
    if touch:
        now = iso(utcnow())
        db.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now, row["session_id"]))
        db.commit()
    return row


def require_session_user(
    request: Request,
    db: DB,
    settings: Annotated[Settings, Depends(get_settings)],
) -> sqlite3.Row:
    user = session_user(request, db, settings)
    if user is None:
        raise _unauthorized("Sign in required")
    return user


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def bearer_user(
    request: Request,
    db: DB,
    settings: Annotated[Settings, Depends(get_settings)],
) -> sqlite3.Row:
    token = _bearer_token(request)
    if not token:
        raise _unauthorized()

    if token.startswith("atdev_"):
        row = db.execute(
            """
            SELECT u.*
            FROM api_keys k
            JOIN users u ON u.id = k.user_id
            WHERE k.key_hash = ?
              AND k.revoked_at IS NULL
            """,
            (token_digest(token),),
        ).fetchone()
        if row is None:
            raise _unauthorized("Invalid API key")
        db.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE key_hash = ?",
            (iso(utcnow()), token_digest(token)),
        )
        db.commit()
        return row

    try:
        payload = decode_token(token, request.app.state.private_key, settings.issuer)
    except Exception as exc:  # jwt.PyJWTError and malformed values
        raise _unauthorized("Invalid or expired token") from exc

    if payload.get("token_use") != "access":
        raise _unauthorized("Invalid token type")
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.isdigit():
        raise _unauthorized("Invalid token subject")
    row = db.execute("SELECT * FROM users WHERE id = ?", (int(subject),)).fetchone()
    if row is None:
        raise _unauthorized("Account no longer exists")
    return row


def current_user(
    request: Request,
    db: DB,
    settings: Annotated[Settings, Depends(get_settings)],
) -> sqlite3.Row:
    user = session_user(request, db, settings)
    if user is not None:
        return user
    return bearer_user(request, db, settings)


def require_admin(
    settings: Annotated[Settings, Depends(get_settings)],
    x_admin_token: Annotated[str | None, Header()] = None,
) -> None:
    if (
        not settings.admin_token
        or not x_admin_token
        or not hmac.compare_digest(x_admin_token, settings.admin_token)
    ):
        raise HTTPException(status_code=403, detail="Admin access denied")


def create_session(
    db: sqlite3.Connection,
    settings: Settings,
    request: Request,
    user_id: int,
    *,
    remember: bool,
) -> tuple[str, int]:
    token = new_token(32)
    now = iso(utcnow())
    ttl = settings.remember_ttl_seconds if remember else settings.session_ttl_seconds
    db.execute(
        """
        INSERT INTO sessions
            (user_id, token_hash, user_agent, ip, created_at, last_seen_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            token_digest(token),
            request.headers.get("user-agent", "")[:512],
            client_ip(request, settings),
            now,
            now,
            future(ttl),
        ),
    )
    db.commit()
    return token, ttl


def set_session_cookie(response: Response, settings: Settings, token: str, ttl: int) -> None:
    response.set_cookie(
        key=settings.session_cookie,
        value=token,
        max_age=ttl,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.session_cookie,
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def revoke_current_session(
    request: Request,
    db: sqlite3.Connection,
    settings: Settings,
) -> bool:
    token = request.cookies.get(settings.session_cookie)
    if not token:
        return False
    cursor = db.execute(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        (iso(utcnow()), token_digest(token)),
    )
    db.commit()
    return cursor.rowcount > 0
