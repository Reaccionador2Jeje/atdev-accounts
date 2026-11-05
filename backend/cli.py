from __future__ import annotations

import argparse
import json
import re
import secrets
import sys

from .config import Settings
from .db import connect, init_db
from .oauth_utils import SUPPORTED_SCOPES
from .security import hash_client_secret, iso, new_token, utcnow


def _unique_client_id(db, name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "client"
    for _ in range(10):
        candidate = f"{base}-{secrets.token_hex(3)}"
        if db.execute("SELECT 1 FROM oauth_clients WHERE client_id = ?", (candidate,)).fetchone() is None:
            return candidate
    return f"client-{new_token(8)}"


def create_client(args) -> int:
    scopes = list(dict.fromkeys(args.scope or ["openid", "profile", "email"]))
    for scope in scopes:
        if scope not in SUPPORTED_SCOPES:
            print(f"Unsupported scope: {scope}", file=sys.stderr)
            return 2
    if not args.redirect_uri:
        print("At least one --redirect-uri is required", file=sys.stderr)
        return 2

    settings = Settings.from_env()
    init_db(settings.db_path)
    db = connect(settings.db_path)
    try:
        client_id = args.client_id or _unique_client_id(db, args.name)
        secret = None
        secret_hash = None
        if not args.public:
            secret = args.secret or new_token(32)
            if len(secret) < 16:
                print("Client secret must be at least 16 characters", file=sys.stderr)
                return 2
            secret_hash = hash_client_secret(secret)
        db.execute(
            """
            INSERT INTO oauth_clients
                (client_id, client_secret_hash, name, redirect_uris, scopes,
                 is_confidential, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                secret_hash,
                args.name,
                json.dumps(args.redirect_uri),
                " ".join(scopes),
                0 if args.public else 1,
                iso(utcnow()),
            ),
        )
        db.commit()
    finally:
        db.close()

    output = {
        "client_id": client_id,
        "name": args.name,
        "redirect_uris": args.redirect_uri,
        "scopes": scopes,
        "public": bool(args.public),
        "client_secret": secret,
    }
    print(json.dumps(output, indent=2))
    return 0


def list_clients(_args) -> int:
    settings = Settings.from_env()
    init_db(settings.db_path)
    db = connect(settings.db_path)
    try:
        rows = db.execute("SELECT * FROM oauth_clients ORDER BY created_at DESC").fetchall()
    finally:
        db.close()
    for row in rows:
        print(
            json.dumps(
                {
                    "client_id": row["client_id"],
                    "name": row["name"],
                    "redirect_uris": json.loads(row["redirect_uris"]),
                    "scopes": row["scopes"].split(),
                    "confidential": bool(row["is_confidential"]),
                    "created_at": row["created_at"],
                }
            )
        )
    return 0


def delete_client(args) -> int:
    settings = Settings.from_env()
    init_db(settings.db_path)
    db = connect(settings.db_path)
    try:
        cursor = db.execute("DELETE FROM oauth_clients WHERE client_id = ?", (args.client_id,))
        db.commit()
    finally:
        db.close()
    if cursor.rowcount == 0:
        print("Client not found", file=sys.stderr)
        return 1
    print(f"Deleted {args.client_id}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-client", help="Register an OAuth/OIDC client")
    create.add_argument("--name", required=True)
    create.add_argument("--client-id")
    create.add_argument("--redirect-uri", action="append", help="Can be repeated")
    create.add_argument("--scope", action="append", choices=list(SUPPORTED_SCOPES))
    create.add_argument("--public", action="store_true", help="Public client using PKCE")
    create.add_argument("--secret", help="Client secret (generated when omitted)")
    create.set_defaults(func=create_client)

    listing = sub.add_parser("list-clients", help="List registered clients")
    listing.set_defaults(func=list_clients)

    delete = sub.add_parser("delete-client", help="Delete a client")
    delete.add_argument("client_id")
    delete.set_defaults(func=delete_client)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
