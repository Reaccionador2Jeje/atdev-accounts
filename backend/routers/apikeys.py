from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from ..deps import DB, current_user
from ..schemas import ApiKeyCreateIn, ApiKeyCreated, ApiKeyOut
from ..security import generate_api_key, iso, utcnow

router = APIRouter(prefix="/api/account/api-keys", tags=["api-keys"])

UserDep = Annotated[sqlite3.Row, Depends(current_user)]


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(user: UserDep, db: DB) -> list[ApiKeyOut]:
    rows = db.execute(
        """
        SELECT id, name, key_prefix, created_at, last_used_at
        FROM api_keys
        WHERE user_id = ? AND revoked_at IS NULL
        ORDER BY created_at DESC
        """,
        (user["id"],),
    ).fetchall()
    return [
        ApiKeyOut(
            id=row["id"],
            name=row["name"],
            prefix=row["key_prefix"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
        )
        for row in rows
    ]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(payload: ApiKeyCreateIn, user: UserDep, db: DB) -> ApiKeyCreated:
    raw, prefix, digest = generate_api_key()
    now = iso(utcnow())
    cursor = db.execute(
        """
        INSERT INTO api_keys (user_id, name, key_prefix, key_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user["id"], payload.name, prefix, digest, now),
    )
    db.commit()
    return ApiKeyCreated(
        id=int(cursor.lastrowid),
        name=payload.name,
        prefix=prefix,
        created_at=now,
        last_used_at=None,
        key=raw,
    )


@router.delete("/{key_id}")
def revoke_api_key(key_id: int, user: UserDep, db: DB) -> dict[str, bool]:
    cursor = db.execute(
        """
        UPDATE api_keys SET revoked_at = ?
        WHERE id = ? AND user_id = ? AND revoked_at IS NULL
        """,
        (iso(utcnow()), key_id, user["id"]),
    )
    db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"ok": True}
