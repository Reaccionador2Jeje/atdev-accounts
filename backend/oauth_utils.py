from __future__ import annotations

import html
import json
import sqlite3
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi.responses import JSONResponse, RedirectResponse

from .config import Settings
from .security import (
    future,
    iso,
    make_access_token,
    make_id_token,
    new_token,
    token_digest,
    utcnow,
    verify_client_secret,
)

SUPPORTED_SCOPES = ("openid", "profile", "email", "offline_access")

SCOPE_DESCRIPTIONS = {
    "openid": "Verify your identity (required for sign-in)",
    "profile": "Read your name and basic profile",
    "email": "Read your email address",
    "offline_access": "Stay signed in and refresh access without asking again",
}


def parse_scopes(raw: str | None, default: tuple[str, ...] = ("openid",)) -> list[str]:
    if not raw:
        return list(default)
    seen: list[str] = []
    for part in raw.replace(",", " ").split():
        if part not in seen:
            seen.append(part)
    return seen


def get_client(db: sqlite3.Connection, client_id: str) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()


def client_redirect_uris(client: sqlite3.Row) -> list[str]:
    try:
        value = json.loads(client["redirect_uris"])
    except (TypeError, ValueError):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def client_scopes(client: sqlite3.Row) -> list[str]:
    return [scope for scope in client["scopes"].split() if scope]


def validate_scopes(requested: list[str], client: sqlite3.Row) -> str | None:
    allowed = set(client_scopes(client))
    for scope in requested:
        if scope not in SUPPORTED_SCOPES:
            return f"Unsupported scope: {scope}"
        if scope not in allowed:
            return f"Scope not allowed for this client: {scope}"
    return None


def build_redirect(redirect_uri: str, params: dict[str, Any]) -> str:
    parts = urlsplit(redirect_uri)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.extend((key, str(value)) for key, value in params.items() if value is not None)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def redirect_response(redirect_uri: str, params: dict[str, Any], status_code: int = 303) -> RedirectResponse:
    return RedirectResponse(build_redirect(redirect_uri, params), status_code=status_code)


def oauth_error(
    status_code: int,
    error: str,
    description: str = "",
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload: dict[str, str] = {"error": error}
    if description:
        payload["error_description"] = description
    response = JSONResponse(payload, status_code=status_code, headers=headers)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def requires_pkce(client: sqlite3.Row) -> bool:
    return not bool(client["is_confidential"])


def authenticate_client(
    db: sqlite3.Connection,
    client_id: str | None,
    client_secret: str | None,
) -> tuple[sqlite3.Row | None, JSONResponse | None]:
    if not client_id:
        return None, oauth_error(401, "invalid_client", "Missing client_id")
    client = get_client(db, client_id)
    if client is None:
        return None, oauth_error(401, "invalid_client", "Unknown client")
    if bool(client["is_confidential"]):
        if not client_secret or not verify_client_secret(client_secret, client["client_secret_hash"]):
            return None, oauth_error(
                401,
                "invalid_client",
                "Invalid client credentials",
                headers={"WWW-Authenticate": 'Basic realm="oauth"'},
            )
    return client, None


def issue_tokens(
    db: sqlite3.Connection,
    settings: Settings,
    private_key,
    user: sqlite3.Row,
    client_id: str,
    scopes: list[str],
    *,
    nonce: str | None = None,
) -> dict[str, Any]:
    scope_string = " ".join(scopes)
    access_token, exp_ts = make_access_token(
        private_key,
        issuer=settings.issuer,
        user_id=user["id"],
        client_id=client_id,
        scopes=scope_string,
        ttl_seconds=settings.access_token_ttl_seconds,
    )
    now_ts = int(utcnow().timestamp())
    result: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": max(1, exp_ts - now_ts),
        "scope": scope_string,
    }

    if "openid" in scopes:
        result["id_token"] = make_id_token(
            private_key,
            issuer=settings.issuer,
            user_id=user["id"],
            client_id=client_id,
            name=user["name"],
            email=user["email"],
            email_verified=bool(user["email_verified"]),
            scopes=scopes,
            ttl_seconds=settings.id_token_ttl_seconds,
            nonce=nonce,
        )

    if "offline_access" in scopes:
        refresh_token = new_token(40)
        now = iso(utcnow())
        db.execute(
            """
            INSERT INTO oauth_refresh_tokens
                (token_hash, client_id, user_id, scopes, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                token_digest(refresh_token),
                client_id,
                user["id"],
                scope_string,
                now,
                future(settings.refresh_token_ttl_seconds),
            ),
        )
        result["refresh_token"] = refresh_token

    return result


def render_consent(
    *,
    request_id: str,
    client_name: str,
    redirect_uri: str,
    scopes: list[str],
    user_name: str,
    app_name: str,
) -> str:
    scope_rows = "".join(
        f"<li><strong>{html.escape(scope)}</strong><span>{html.escape(SCOPE_DESCRIPTIONS.get(scope, scope))}</span></li>"
        for scope in scopes
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {html.escape(client_name)} — {html.escape(app_name)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color: #f8fafc;
    background: radial-gradient(circle at top, rgba(124,58,237,.25), transparent 55%), #0b1026;
  }}
  .card {{
    width: 100%; max-width: 480px; background: #131a33; border: 1px solid rgba(148,163,184,.25);
    border-radius: 18px; padding: 28px; box-shadow: 0 30px 70px -40px rgba(0,0,0,.9);
  }}
  h1 {{ margin: 0 0 6px; font-size: 1.35rem; }}
  .muted {{ color: #94a3b8; font-size: .92rem; margin: 0 0 20px; }}
  .redirect {{ font-size: .8rem; color: #94a3b8; background: #0b1026; padding: 10px 12px; border-radius: 10px;
    overflow-wrap: anywhere; border: 1px solid rgba(148,163,184,.18); margin-bottom: 20px; }}
  ul {{ list-style: none; padding: 0; margin: 0 0 24px; display: grid; gap: 10px; }}
  li {{ display: grid; gap: 2px; padding: 12px 14px; border-radius: 12px; background: rgba(124,58,237,.12);
    border: 1px solid rgba(124,58,237,.3); }}
  li span {{ color: #cbd5f5; font-size: .86rem; }}
  .actions {{ display: flex; gap: 10px; }}
  button {{ flex: 1; font: inherit; font-weight: 600; padding: 12px 16px; border-radius: 10px; cursor: pointer; border: 1px solid transparent; }}
  .approve {{ background: #7c3aed; color: white; }}
  .approve:hover {{ background: #6d28d9; }}
  .deny {{ background: transparent; color: #cbd5f5; border-color: rgba(148,163,184,.35); }}
  .deny:hover {{ background: rgba(148,163,184,.1); }}
</style>
</head>
<body>
  <main class="card">
    <h1>Authorize {html.escape(client_name)}</h1>
    <p class="muted">Signed in as {html.escape(user_name)}. This app wants to access your AtDev account.</p>
    <div class="redirect">Redirects to: {html.escape(redirect_uri)}</div>
    <ul>{scope_rows}</ul>
    <form method="post" action="/oauth/authorize/consent">
      <input type="hidden" name="request_id" value="{html.escape(request_id)}">
      <div class="actions">
        <button class="deny" type="submit" name="decision" value="deny">Cancel</button>
        <button class="approve" type="submit" name="decision" value="approve">Authorize</button>
      </div>
    </form>
  </main>
</body>
</html>"""
