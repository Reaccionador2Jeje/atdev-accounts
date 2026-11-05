from __future__ import annotations

import base64
import binascii
import sqlite3
from typing import Annotated
from urllib.parse import quote, unquote_plus

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ..config import Settings
from ..deps import DB, get_settings, session_user
from ..oauth_utils import (
    SUPPORTED_SCOPES,
    authenticate_client,
    client_redirect_uris,
    get_client,
    issue_tokens,
    oauth_error,
    parse_scopes,
    redirect_response,
    render_consent,
    requires_pkce,
    validate_scopes,
)
from ..security import (
    decode_token,
    future,
    iso,
    new_token,
    public_jwk,
    token_digest,
    utcnow,
    verify_pkce,
)

router = APIRouter(tags=["oauth"])

SettingsDep = Annotated[Settings, Depends(get_settings)]

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _bad_request(message: str) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><body><h1>Invalid authorization request</h1><p>{message}</p></body></html>",
        status_code=400,
        headers=NO_STORE,
    )


def _issue_code(
    db: sqlite3.Connection,
    settings: Settings,
    *,
    user_id: int,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    nonce: str,
    code_challenge: str,
    code_challenge_method: str,
) -> RedirectResponse:
    code = new_token(32)
    now = iso(utcnow())
    db.execute(
        """
        INSERT INTO oauth_codes
            (code_hash, client_id, user_id, redirect_uri, scopes, code_challenge,
             code_challenge_method, nonce, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token_digest(code),
            client_id,
            user_id,
            redirect_uri,
            " ".join(scopes),
            code_challenge,
            code_challenge_method,
            nonce,
            now,
            future(settings.auth_code_ttl_seconds),
        ),
    )
    db.commit()
    params = {"code": code}
    if state:
        params["state"] = state
    return redirect_response(redirect_uri, params)


@router.get("/oauth/authorize")
def authorize(
    request: Request,
    db: DB,
    settings: SettingsDep,
    response_type: str = Query("code"),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid profile email"),
    state: str = Query(""),
    nonce: str = Query(""),
    code_challenge: str = Query(""),
    code_challenge_method: str = Query(""),
    prompt: str = Query(""),
) -> Response:
    client = get_client(db, client_id)
    if client is None:
        return _bad_request("Unknown client_id.")
    if redirect_uri not in client_redirect_uris(client):
        return _bad_request("redirect_uri is not registered for this client.")

    def error(code: str, description: str, status: int = 303) -> RedirectResponse:
        params = {"error": code, "error_description": description}
        if state:
            params["state"] = state
        return redirect_response(redirect_uri, params, status_code=status)

    if response_type != "code":
        return error("unsupported_response_type", "Only response_type=code is supported.")

    scopes = parse_scopes(scope)
    scope_error = validate_scopes(scopes, client)
    if scope_error:
        return error("invalid_scope", scope_error)

    method = code_challenge_method or ("S256" if code_challenge else "")
    if method and method.upper() not in ("S256", "PLAIN"):
        return error("invalid_request", "Unsupported code_challenge_method.")
    if code_challenge and not method:
        return error("invalid_request", "code_challenge_method is required.")
    if requires_pkce(client) and not code_challenge:
        return error("invalid_request", "PKCE code_challenge is required for public clients.")

    user = session_user(request, db, settings)
    if user is None:
        if prompt == "none":
            return error("login_required", "The user is not signed in.")
        next_path = request.url.path
        if request.url.query:
            next_path += "?" + request.url.query
        return RedirectResponse(f"/?next={quote(next_path, safe='')}", status_code=303)

    grant = db.execute(
        "SELECT scopes FROM oauth_grants WHERE user_id = ? AND client_id = ?",
        (user["id"], client_id),
    ).fetchone()
    granted = set(grant["scopes"].split()) if grant else set()
    if set(scopes).issubset(granted):
        return _issue_code(
            db,
            settings,
            user_id=user["id"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=method,
        )

    if prompt == "none":
        return error("consent_required", "The user has not granted these scopes.")

    request_id = new_token(24)
    now = iso(utcnow())
    db.execute(
        """
        INSERT INTO oauth_authorize_requests
            (request_id, user_id, client_id, redirect_uri, scopes, state, nonce,
             code_challenge, code_challenge_method, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            user["id"],
            client_id,
            redirect_uri,
            " ".join(scopes),
            state,
            nonce,
            code_challenge,
            method,
            now,
            future(600),
        ),
    )
    db.commit()

    body = render_consent(
        request_id=request_id,
        client_name=client["name"],
        redirect_uri=redirect_uri,
        scopes=scopes,
        user_name=user["name"],
        app_name=settings.app_name,
    )
    return HTMLResponse(body, headers=NO_STORE)


@router.post("/oauth/authorize/consent")
def authorize_consent(
    request: Request,
    db: DB,
    settings: SettingsDep,
    request_id: Annotated[str, Form()],
    decision: Annotated[str, Form()],
) -> Response:
    user = session_user(request, db, settings)
    if user is None:
        return _bad_request("Your session expired. Go back and sign in again.")

    row = db.execute(
        "SELECT * FROM oauth_authorize_requests WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if (
        row is None
        or row["user_id"] != user["id"]
        or row["used_at"] is not None
        or row["expires_at"] <= iso(utcnow())
    ):
        return _bad_request("This authorization request is invalid or has expired.")

    cursor = db.execute(
        "UPDATE oauth_authorize_requests SET used_at = ? WHERE request_id = ? AND used_at IS NULL",
        (iso(utcnow()), request_id),
    )
    if cursor.rowcount == 0:
        db.rollback()
        return _bad_request("This authorization request has already been used.")
    db.commit()

    params: dict[str, str] = {}
    if row["state"]:
        params["state"] = row["state"]

    if decision != "approve":
        params.update(error="access_denied", error_description="The user denied the request.")
        return redirect_response(row["redirect_uri"], params)

    now = iso(utcnow())
    db.execute(
        """
        INSERT INTO oauth_grants (user_id, client_id, scopes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (user_id, client_id)
        DO UPDATE SET scopes = excluded.scopes, updated_at = excluded.updated_at
        """,
        (user["id"], row["client_id"], row["scopes"], now, now),
    )
    db.commit()

    return _issue_code(
        db,
        settings,
        user_id=user["id"],
        client_id=row["client_id"],
        redirect_uri=row["redirect_uri"],
        scopes=row["scopes"].split(),
        state=row["state"],
        nonce=row["nonce"],
        code_challenge=row["code_challenge"],
        code_challenge_method=row["code_challenge_method"],
    )


def _basic_credentials(request: Request) -> tuple[str | None, str | None]:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        return None, None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None, None
    username, _, password = decoded.partition(":")
    return unquote_plus(username), unquote_plus(password)


@router.post("/oauth/token")
async def token(request: Request, db: DB, settings: SettingsDep) -> Response:
    content_type = request.headers.get("content-type", "")
    if not (
        content_type.startswith("application/x-www-form-urlencoded")
        or content_type.startswith("multipart/form-data")
    ):
        return oauth_error(400, "invalid_request", "Expected form-encoded body.")
    form = await request.form()

    basic_id, basic_secret = _basic_credentials(request)
    client_id = basic_id or (str(form["client_id"]) if "client_id" in form else None)
    client_secret = basic_secret or (str(form["client_secret"]) if "client_secret" in form else None)

    client, error = authenticate_client(db, client_id, client_secret)
    if error is not None:
        return error

    grant_type = str(form.get("grant_type", ""))

    if grant_type == "authorization_code":
        code = str(form.get("code", ""))
        redirect_uri = str(form.get("redirect_uri", ""))
        verifier = form.get("code_verifier")
        if not code:
            return oauth_error(400, "invalid_request", "Missing code.")

        row = db.execute(
            "SELECT * FROM oauth_codes WHERE code_hash = ?",
            (token_digest(code),),
        ).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] <= iso(utcnow()):
            return oauth_error(400, "invalid_grant", "Authorization code is invalid or expired.")
        if row["client_id"] != client["client_id"]:
            return oauth_error(400, "invalid_grant", "Authorization code was issued to another client.")
        if row["redirect_uri"] != redirect_uri:
            return oauth_error(400, "invalid_grant", "redirect_uri does not match.")
        if not verify_pkce(
            str(verifier) if verifier is not None else None,
            row["code_challenge"],
            row["code_challenge_method"],
        ):
            return oauth_error(400, "invalid_grant", "PKCE verification failed.")

        cursor = db.execute(
            "UPDATE oauth_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
            (iso(utcnow()), row["id"]),
        )
        if cursor.rowcount == 0:
            db.rollback()
            return oauth_error(400, "invalid_grant", "Authorization code has already been used.")
        db.commit()

        user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
        if user is None:
            return oauth_error(400, "invalid_grant", "Account no longer exists.")

        tokens = issue_tokens(
            db,
            settings,
            request.app.state.private_key,
            user,
            client["client_id"],
            row["scopes"].split(),
            nonce=row["nonce"] or None,
        )
        db.commit()
        return JSONResponse(tokens, headers=NO_STORE)

    if grant_type == "refresh_token":
        raw = str(form.get("refresh_token", ""))
        if not raw:
            return oauth_error(400, "invalid_request", "Missing refresh_token.")
        row = db.execute(
            "SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?",
            (token_digest(raw),),
        ).fetchone()
        if (
            row is None
            or row["client_id"] != client["client_id"]
            or row["revoked_at"] is not None
            or row["expires_at"] <= iso(utcnow())
        ):
            return oauth_error(400, "invalid_grant", "Refresh token is invalid or expired.")

        original_scopes = row["scopes"].split()
        requested = parse_scopes(str(form["scope"])) if "scope" in form else original_scopes
        if not set(requested).issubset(set(original_scopes)):
            return oauth_error(400, "invalid_scope", "Requested scope exceeds the original grant.")

        db.execute(
            "UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (iso(utcnow()), row["id"]),
        )
        db.commit()

        user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
        if user is None:
            return oauth_error(400, "invalid_grant", "Account no longer exists.")

        tokens = issue_tokens(
            db,
            settings,
            request.app.state.private_key,
            user,
            client["client_id"],
            requested,
        )
        db.commit()
        return JSONResponse(tokens, headers=NO_STORE)

    return oauth_error(400, "unsupported_grant_type", "Supported: authorization_code, refresh_token.")


@router.get("/oauth/userinfo")
def userinfo(request: Request, db: DB, settings: SettingsDep) -> Response:
    header = request.headers.get("authorization", "")
    scheme, _, raw = header.partition(" ")
    if scheme.lower() != "bearer" or not raw.strip() or raw.startswith("atdev_"):
        return oauth_error(401, "invalid_token", "A valid access token is required.")
    try:
        payload = decode_token(raw.strip(), request.app.state.private_key, settings.issuer)
    except Exception:
        return oauth_error(401, "invalid_token", "The access token is invalid or expired.")
    if payload.get("token_use") != "access":
        return oauth_error(401, "invalid_token", "Not an access token.")

    scopes = str(payload.get("scope", "")).split()
    if "openid" not in scopes:
        return oauth_error(403, "insufficient_scope", "The openid scope is required.")

    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.isdigit():
        return oauth_error(401, "invalid_token", "Invalid token subject.")
    user = db.execute("SELECT * FROM users WHERE id = ?", (int(subject),)).fetchone()
    if user is None:
        return oauth_error(401, "invalid_token", "Account no longer exists.")

    claims: dict[str, object] = {"sub": str(user["id"])}
    if "profile" in scopes:
        claims.update(
            {
                "name": user["name"],
                "preferred_username": user["email"].split("@")[0],
                "updated_at": user["updated_at"],
            }
        )
    if "email" in scopes:
        claims.update(
            {
                "email": user["email"],
                "email_verified": bool(user["email_verified"]),
            }
        )
    return JSONResponse(claims, headers=NO_STORE)


@router.post("/oauth/revoke")
async def revoke(request: Request, db: DB, settings: SettingsDep) -> Response:
    content_type = request.headers.get("content-type", "")
    if not (
        content_type.startswith("application/x-www-form-urlencoded")
        or content_type.startswith("multipart/form-data")
    ):
        return oauth_error(400, "invalid_request", "Expected form-encoded body.")
    form = await request.form()
    raw = str(form.get("token", ""))
    if raw:
        db.execute(
            """
            UPDATE oauth_refresh_tokens SET revoked_at = ?
            WHERE token_hash = ? AND revoked_at IS NULL
            """,
            (iso(utcnow()), token_digest(raw)),
        )
        db.commit()
    return JSONResponse({"ok": True}, headers=NO_STORE)


@router.get("/.well-known/openid-configuration")
def openid_configuration(settings: SettingsDep) -> Response:
    payload = {
        "issuer": settings.issuer,
        "authorization_endpoint": f"{settings.issuer}/oauth/authorize",
        "token_endpoint": f"{settings.issuer}/oauth/token",
        "userinfo_endpoint": f"{settings.issuer}/oauth/userinfo",
        "jwks_uri": settings.jwks_url,
        "revocation_endpoint": f"{settings.issuer}/oauth/revoke",
        "scopes_supported": list(SUPPORTED_SCOPES),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "name",
            "preferred_username",
            "email",
            "email_verified",
            "updated_at",
        ],
    }
    return JSONResponse(payload, headers={"Cache-Control": "public, max-age=300"})


@router.get("/.well-known/jwks.json")
def jwks(request: Request) -> Response:
    key = public_jwk(request.app.state.private_key)
    return JSONResponse({"keys": [key]}, headers={"Cache-Control": "public, max-age=300"})
