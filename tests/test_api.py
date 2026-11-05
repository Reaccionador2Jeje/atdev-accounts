from __future__ import annotations

import base64
import hashlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.main import create_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("APP_ORIGIN", "http://testserver")
    monkeypatch.setenv("SECURE_COOKIES", "false")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("DEFAULT_CLIENT_REDIRECT_URIS", "")
    app = create_app(Settings.from_env())
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def user(client):
    response = client.post(
        "/api/auth/register",
        json={"name": "Ada Lovelace", "email": "ada@example.com", "password": "correct horse"},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture()
def public_client(client):
    response = client.post(
        "/api/admin/clients",
        headers={"X-Admin-Token": "test-admin-token"},
        json={
            "name": "Test App",
            "redirect_uris": ["https://app.example/callback"],
            "scopes": ["openid", "profile", "email", "offline_access"],
            "public": True,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def pkce_pair() -> tuple[str, str]:
    verifier = "test-verifier-" + "x" * 40
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def register(client, email="ada@example.com", password="correct horse"):
    return client.post(
        "/api/auth/register",
        json={"name": "Ada Lovelace", "email": email, "password": password},
    )


def test_health_and_frontend(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/").status_code == 200
    assert client.get("/account.html").status_code == 200
    assert client.get("/app.js").status_code == 200
    assert client.get("/.env").status_code == 404


def test_seed_clients_from_env(tmp_path, monkeypatch):
    seeds = [
        {
            "client_id": "openweb-linux",
            "name": "OpenWeb Linux",
            "redirect_uris": ["https://example.github.io/openweb/oauth/callback"],
            "scopes": ["openid", "profile", "email", "offline_access"],
            "public": True,
        },
        {
            "client_id": "librecoding",
            "name": "LibreCoding",
            "redirect_uris": ["https://example.github.io/librecoding/oauth/callback"],
            "scopes": ["openid", "profile", "email"],
            "public": True,
        },
    ]
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("APP_ORIGIN", "http://testserver")
    monkeypatch.setenv("SECURE_COOKIES", "false")
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("DEFAULT_CLIENT_REDIRECT_URIS", "")
    monkeypatch.setenv("SEED_CLIENTS", json.dumps(seeds))

    app = create_app(Settings.from_env())
    with TestClient(app) as test_client:
        response = test_client.get(
            "/api/admin/clients", headers={"X-Admin-Token": "test-admin-token"}
        )
        assert response.status_code == 200
        clients = {item["client_id"]: item for item in response.json()}
        assert set(clients) == {"openweb-linux", "librecoding"}
        assert clients["openweb-linux"]["redirect_uris"] == [
            "https://example.github.io/openweb/oauth/callback"
        ]
        assert clients["librecoding"]["scopes"] == ["openid", "profile", "email"]
        assert clients["librecoding"]["is_confidential"] is False


def test_register_login_me_logout(client):
    response = register(client)
    assert response.status_code == 201
    assert response.json()["email"] == "ada@example.com"
    assert "atdev_session" in response.cookies

    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["name"] == "Ada Lovelace"

    duplicate = register(client)
    assert duplicate.status_code == 409

    wrong = client.post(
        "/api/auth/login", json={"email": "ada@example.com", "password": "nope"}
    )
    assert wrong.status_code == 401

    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/auth/me").status_code == 401

    login = client.post(
        "/api/auth/login",
        json={"email": "ada@example.com", "password": "correct horse"},
    )
    assert login.status_code == 200
    assert client.get("/api/auth/me").status_code == 200


def test_password_change_revokes_other_sessions(client, user):
    other = TestClient(client.app)
    with other:
        login = other.post(
            "/api/auth/login",
            json={"email": "ada@example.com", "password": "correct horse"},
        )
        assert login.status_code == 200
        assert other.get("/api/auth/me").status_code == 200

    response = client.post(
        "/api/account/password",
        json={"current_password": "correct horse", "new_password": "new correct horse"},
    )
    assert response.status_code == 200, response.text
    assert other.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me").status_code == 200

    bad_login = client.post(
        "/api/auth/login",
        json={"email": "ada@example.com", "password": "correct horse"},
    )
    assert bad_login.status_code == 401


def test_api_keys_and_bearer_auth(client, user):
    created = client.post("/api/account/api-keys", json={"name": "laptop"})
    assert created.status_code == 201
    payload = created.json()
    assert payload["key"].startswith("atdev_")

    anonymous = TestClient(client.app)
    with anonymous:
        response = anonymous.get(
            "/api/account",
            headers={"Authorization": f"Bearer {payload['key']}"},
        )
        assert response.status_code == 200
        assert response.json()["email"] == "ada@example.com"

        listed = anonymous.get(
            "/api/account/api-keys",
            headers={"Authorization": f"Bearer {payload['key']}"},
        )
        assert listed.status_code == 200
        assert listed.json()[0]["prefix"]

    revoked = client.delete(f"/api/account/api-keys/{payload['id']}")
    assert revoked.status_code == 200

    anonymous = TestClient(client.app)
    with anonymous:
        response = anonymous.get(
            "/api/account",
            headers={"Authorization": f"Bearer {payload['key']}"},
        )
        assert response.status_code == 401


def test_origin_check_blocks_cross_site_posts(client):
    response = client.post(
        "/api/auth/login",
        headers={"Origin": "https://evil.example"},
        json={"email": "ada@example.com", "password": "correct horse"},
    )
    assert response.status_code == 403


def test_account_update_and_delete(client, user):
    updated = client.patch("/api/account", json={"name": "Ada L."})
    assert updated.status_code == 200
    assert updated.json()["name"] == "Ada L."

    wrong = client.request("DELETE", "/api/account", json={"password": "wrong"})
    assert wrong.status_code == 400

    deleted = client.request("DELETE", "/api/account", json={"password": "correct horse"})
    assert deleted.status_code == 200
    assert client.get("/api/auth/me").status_code == 401

    login = client.post(
        "/api/auth/login",
        json={"email": "ada@example.com", "password": "correct horse"},
    )
    assert login.status_code == 401


def test_oauth_authorization_code_flow_with_pkce(client, user, public_client):
    verifier, challenge = pkce_pair()
    params = {
        "response_type": "code",
        "client_id": public_client["client_id"],
        "redirect_uri": "https://app.example/callback",
        "scope": "openid profile email offline_access",
        "state": "state-123",
        "nonce": "nonce-456",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    authorize = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert authorize.status_code == 200
    assert "Authorize Test App" in authorize.text
    request_id = re.search(r'name="request_id" value="([^"]+)"', authorize.text).group(1)

    consent = client.post(
        "/oauth/authorize/consent",
        data={"request_id": request_id, "decision": "approve"},
        follow_redirects=False,
    )
    assert consent.status_code == 303
    location = consent.headers["location"]
    assert location.startswith("https://app.example/callback?")
    assert "state=state-123" in location
    code = re.search(r"[?&]code=([^&]+)", location).group(1)

    token = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example/callback",
            "client_id": public_client["client_id"],
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    tokens = token.json()
    assert tokens["token_type"] == "Bearer"
    assert "id_token" in tokens
    assert "refresh_token" in tokens

    reused = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://app.example/callback",
            "client_id": public_client["client_id"],
            "code_verifier": verifier,
        },
    )
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"

    userinfo = client.get(
        "/oauth/userinfo",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert userinfo.status_code == 200
    claims = userinfo.json()
    assert claims["email"] == "ada@example.com"
    assert claims["name"] == "Ada Lovelace"

    refreshed = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": public_client["client_id"],
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["refresh_token"] != tokens["refresh_token"]

    old_refresh = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": public_client["client_id"],
        },
    )
    assert old_refresh.status_code == 400

    connections = client.get("/api/account/connections")
    assert connections.status_code == 200
    assert connections.json()[0]["client_id"] == public_client["client_id"]


def test_oauth_requires_login_and_pkce(client, public_client):
    verifier, challenge = pkce_pair()
    params = {
        "response_type": "code",
        "client_id": public_client["client_id"],
        "redirect_uri": "https://app.example/callback",
        "scope": "openid",
        "state": "abc",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    response = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/?next=")

    login = register(client)
    assert login.status_code == 201

    missing_pkce = client.get(
        "/oauth/authorize",
        params={**params, "code_challenge": "", "code_challenge_method": ""},
        follow_redirects=False,
    )
    assert missing_pkce.status_code == 303
    assert "error=invalid_request" in missing_pkce.headers["location"]

    error_redirect = client.get(
        "/oauth/authorize",
        params={
            **params,
            "prompt": "none",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert "error=consent_required" in error_redirect.headers["location"]


def test_discovery_jwks_and_security_headers(client):
    discovery = client.get("/.well-known/openid-configuration")
    assert discovery.status_code == 200
    body = discovery.json()
    assert body["issuer"] == "http://testserver"
    assert body["token_endpoint"].endswith("/oauth/token")

    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    key = jwks.json()["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"

    index = client.get("/")
    assert index.headers["x-content-type-options"] == "nosniff"
    assert index.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" in index.headers


def test_confidential_client_can_use_client_secret(client, user):
    created = client.post(
        "/api/admin/clients",
        headers={"X-Admin-Token": "test-admin-token"},
        json={
            "name": "Confidential App",
            "redirect_uris": ["https://conf.example/cb"],
            "scopes": ["openid", "email"],
        },
    )
    assert created.status_code == 201
    confidential = created.json()
    assert confidential["client_secret"]

    params = {
        "response_type": "code",
        "client_id": confidential["client_id"],
        "redirect_uri": "https://conf.example/cb",
        "scope": "openid email",
        "state": "s",
    }
    authorize = client.get("/oauth/authorize", params=params, follow_redirects=False)
    request_id = re.search(r'name="request_id" value="([^"]+)"', authorize.text).group(1)
    consent = client.post(
        "/oauth/authorize/consent",
        data={"request_id": request_id, "decision": "approve"},
        follow_redirects=False,
    )
    code = re.search(r"[?&]code=([^&]+)", consent.headers["location"]).group(1)

    basic = base64.b64encode(
        f"{confidential['client_id']}:{confidential['client_secret']}".encode()
    ).decode()
    token = client.post(
        "/oauth/token",
        headers={"Authorization": f"Basic {basic}"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://conf.example/cb",
        },
    )
    assert token.status_code == 200, token.text
    assert token.json()["scope"] == "openid email"
