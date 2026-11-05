from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..config import Settings
from ..deps import (
    DB,
    clear_session_cookie,
    create_session,
    current_user,
    get_settings,
    require_session_user,
    revoke_current_session,
    set_session_cookie,
)
from ..schemas import LoginIn, RegisterIn, UserOut
from ..security import hash_password, iso, utcnow, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("/config")
def auth_config(settings: SettingsDep) -> dict[str, object]:
    return {
        "app_name": settings.app_name,
        "issuer": settings.issuer,
        "allow_registration": settings.allow_registration,
        "session_cookie": settings.session_cookie,
    }


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterIn,
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
) -> UserOut:
    if not settings.allow_registration:
        raise HTTPException(status_code=403, detail="Registration is disabled")

    now = iso(utcnow())
    try:
        cursor = db.execute(
            """
            INSERT INTO users (name, email, password_hash, email_verified, created_at, updated_at)
            VALUES (?, ?, ?, 0, ?, ?)
            """,
            (payload.name, payload.email, hash_password(payload.password), now, now),
        )
        db.commit()
    except sqlite3.IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        ) from exc

    user_id = int(cursor.lastrowid)
    token, ttl = create_session(db, settings, request, user_id, remember=payload.remember)
    set_session_cookie(response, settings, token, ttl)

    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return UserOut.from_row(row)


@router.post("/login", response_model=UserOut)
def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
) -> UserOut:
    row = db.execute("SELECT * FROM users WHERE email = ?", (payload.email,)).fetchone()
    if row is None or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, ttl = create_session(db, settings, request, row["id"], remember=payload.remember)
    set_session_cookie(response, settings, token, ttl)
    return UserOut.from_row(row)


@router.get("/me", response_model=UserOut)
def me(user: Annotated[sqlite3.Row, Depends(current_user)]) -> UserOut:
    return UserOut.from_row(user)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
) -> dict[str, bool]:
    revoke_current_session(request, db, settings)
    clear_session_cookie(response, settings)
    return {"ok": True}


@router.post("/logout-all")
def logout_all(
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
    user: Annotated[sqlite3.Row, Depends(require_session_user)],
) -> dict[str, object]:
    now = iso(utcnow())
    cursor = db.execute(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (now, user["id"]),
    )
    db.execute(
        """
        UPDATE oauth_refresh_tokens SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL
        """,
        (now, user["id"]),
    )
    db.commit()
    clear_session_cookie(response, settings)
    return {"ok": True, "revoked": cursor.rowcount}
