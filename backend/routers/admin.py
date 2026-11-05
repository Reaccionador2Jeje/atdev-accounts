from __future__ import annotations

import json
import re
import secrets
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from ..deps import DB, require_admin
from ..oauth_utils import SUPPORTED_SCOPES
from ..schemas import ClientCreateIn, ClientCreated, ClientOut
from ..security import hash_client_secret, iso, new_token, utcnow

router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


def _client_out(row: sqlite3.Row) -> ClientOut:
    return ClientOut(
        client_id=row["client_id"],
        name=row["name"],
        redirect_uris=json.loads(row["redirect_uris"]),
        scopes=row["scopes"].split(),
        is_confidential=bool(row["is_confidential"]),
        created_at=row["created_at"],
    )


def _unique_client_id(db: sqlite3.Connection, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "client"
    for _ in range(10):
        candidate = f"{base}-{secrets.token_hex(3)}"
        exists = db.execute(
            "SELECT 1 FROM oauth_clients WHERE client_id = ?", (candidate,)
        ).fetchone()
        if exists is None:
            return candidate
    return f"client-{new_token(8)}"


@router.get("/clients", response_model=list[ClientOut])
def list_clients(db: DB) -> list[ClientOut]:
    rows = db.execute("SELECT * FROM oauth_clients ORDER BY created_at DESC").fetchall()
    return [_client_out(row) for row in rows]


@router.post("/clients", response_model=ClientCreated, status_code=status.HTTP_201_CREATED)
def create_client(payload: ClientCreateIn, db: DB) -> ClientCreated:
    scopes = [scope for scope in dict.fromkeys(payload.scopes) if scope]
    for scope in scopes:
        if scope not in SUPPORTED_SCOPES:
            raise HTTPException(status_code=400, detail=f"Unsupported scope: {scope}")
    if not scopes:
        raise HTTPException(status_code=400, detail="At least one scope is required")

    client_id = _unique_client_id(db, payload.name)
    secret: str | None = None
    secret_hash: str | None = None
    if not payload.public:
        secret = payload.client_secret or new_token(32)
        if len(secret) < 16:
            raise HTTPException(status_code=400, detail="Client secret must be at least 16 characters")
        secret_hash = hash_client_secret(secret)

    now = iso(utcnow())
    db.execute(
        """
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, name, redirect_uris, scopes, is_confidential, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            secret_hash,
            payload.name,
            json.dumps(payload.redirect_uris),
            " ".join(scopes),
            0 if payload.public else 1,
            now,
        ),
    )
    db.commit()

    return ClientCreated(
        client_id=client_id,
        name=payload.name,
        redirect_uris=payload.redirect_uris,
        scopes=scopes,
        is_confidential=not payload.public,
        created_at=now,
        client_secret=secret,
    )


@router.delete("/clients/{client_id}")
def delete_client(client_id: str, db: DB) -> dict[str, bool]:
    cursor = db.execute("DELETE FROM oauth_clients WHERE client_id = ?", (client_id,))
    db.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"ok": True}
