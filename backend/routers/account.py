from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ..config import Settings
from ..deps import (
    DB,
    clear_session_cookie,
    current_user,
    get_settings,
    require_session_user,
)
from ..schemas import (
    ChangePasswordIn,
    DeleteAccountIn,
    SessionOut,
    UpdateProfileIn,
    UserOut,
)
from ..security import hash_password, iso, utcnow, verify_password

router = APIRouter(prefix="/api/account", tags=["account"])

SettingsDep = Annotated[Settings, Depends(get_settings)]
UserDep = Annotated[sqlite3.Row, Depends(current_user)]


@router.get("", response_model=UserOut)
def get_account(user: UserDep) -> UserOut:
    return UserOut.from_row(user)


@router.patch("", response_model=UserOut)
def update_account(payload: UpdateProfileIn, user: UserDep, db: DB) -> UserOut:
    db.execute(
        "UPDATE users SET name = ?, updated_at = ? WHERE id = ?",
        (payload.name, iso(utcnow()), user["id"]),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    return UserOut.from_row(row)


@router.post("/password")
def change_password(
    payload: ChangePasswordIn,
    user: UserDep,
    db: DB,
) -> dict[str, bool]:
    row = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not verify_password(payload.current_password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    db.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (hash_password(payload.new_password), iso(utcnow()), user["id"]),
    )
    session_id = user["session_id"] if "session_id" in user.keys() else None
    if session_id is not None:
        db.execute(
            """
            UPDATE sessions SET revoked_at = ?
            WHERE user_id = ? AND id != ? AND revoked_at IS NULL
            """,
            (iso(utcnow()), user["id"], session_id),
        )
    else:
        db.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (iso(utcnow()), user["id"]),
        )
    db.execute(
        """
        UPDATE oauth_refresh_tokens SET revoked_at = ?
        WHERE user_id = ? AND revoked_at IS NULL
        """,
        (iso(utcnow()), user["id"]),
    )
    db.commit()
    return {"ok": True}


@router.get("/connections")
def list_connections(user: UserDep, db: DB) -> list[dict[str, object]]:
    rows = db.execute(
        """
        SELECT g.client_id, g.scopes, g.updated_at, c.name
        FROM oauth_grants g
        LEFT JOIN oauth_clients c ON c.client_id = g.client_id
        WHERE g.user_id = ?
        ORDER BY g.updated_at DESC
        """,
        (user["id"],),
    ).fetchall()
    return [
        {
            "client_id": row["client_id"],
            "name": row["name"] or row["client_id"],
            "scopes": row["scopes"].split(),
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


@router.delete("/connections/{client_id}")
def revoke_connection(client_id: str, user: UserDep, db: DB) -> dict[str, bool]:
    cursor = db.execute(
        "DELETE FROM oauth_grants WHERE user_id = ? AND client_id = ?",
        (user["id"], client_id),
    )
    db.execute(
        """
        UPDATE oauth_refresh_tokens SET revoked_at = ?
        WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL
        """,
        (iso(utcnow()), user["id"], client_id),
    )
    db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"ok": True}


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(user: UserDep, db: DB) -> list[SessionOut]:
    current_id = user["session_id"] if "session_id" in user.keys() else None
    rows = db.execute(
        """
        SELECT id, created_at, last_seen_at, expires_at, user_agent, ip
        FROM sessions
        WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
        ORDER BY last_seen_at DESC
        """,
        (user["id"], iso(utcnow())),
    ).fetchall()
    return [
        SessionOut(
            id=row["id"],
            created_at=row["created_at"],
            last_seen_at=row["last_seen_at"],
            expires_at=row["expires_at"],
            user_agent=row["user_agent"],
            ip=row["ip"],
            current=row["id"] == current_id,
        )
        for row in rows
    ]


@router.delete("/sessions/{session_id}")
def delete_session(session_id: int, user: UserDep, db: DB) -> dict[str, bool]:
    cursor = db.execute(
        """
        UPDATE sessions SET revoked_at = ?
        WHERE id = ? AND user_id = ? AND revoked_at IS NULL
        """,
        (iso(utcnow()), session_id, user["id"]),
    )
    db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"ok": True}


@router.delete("/sessions")
def delete_sessions(
    request: Request,
    response: Response,
    user: Annotated[sqlite3.Row, Depends(require_session_user)],
    db: DB,
    settings: SettingsDep,
    keep_current: bool = True,
) -> dict[str, object]:
    now = iso(utcnow())
    if keep_current:
        cursor = db.execute(
            """
            UPDATE sessions SET revoked_at = ?
            WHERE user_id = ? AND id != ? AND revoked_at IS NULL
            """,
            (now, user["id"], user["session_id"]),
        )
    else:
        cursor = db.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (now, user["id"]),
        )
        clear_session_cookie(response, settings)
    db.commit()
    return {"ok": True, "revoked": cursor.rowcount}


@router.delete("")
@router.post("/delete")
def delete_account(
    payload: DeleteAccountIn,
    user: UserDep,
    db: DB,
    response: Response,
    settings: SettingsDep,
) -> dict[str, bool]:
    row = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="Password is incorrect")

    db.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    db.commit()
    clear_session_cookie(response, settings)
    return {"ok": True}
