from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or utcnow()).replace(microsecond=0).isoformat()


def future(seconds: int) -> str:
    return iso(utcnow() + timedelta(seconds=seconds))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _password_encode(salt: bytes, digest: bytes) -> str:
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            b64url(salt),
            b64url(digest),
        )
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return _password_encode(salt, digest)


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if scheme != "scrypt":
            return False
        salt = _decode_b64(salt_b64)
        expected = _decode_b64(digest_b64)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _decode_b64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def generate_api_key() -> tuple[str, str, str]:
    raw = "atdev_" + secrets.token_urlsafe(32)
    return raw, raw[:16], token_digest(raw)


def hash_client_secret(secret: str) -> str:
    return token_digest(secret)


def verify_client_secret(secret: str, expected_hash: str | None) -> bool:
    if not expected_hash:
        return False
    return hmac.compare_digest(token_digest(secret), expected_hash)


def load_or_create_private_key(path: str | Path) -> rsa.RSAPrivateKey:
    key_path = Path(path)
    if key_path.exists():
        data = key_path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("OIDC signing key is not an RSA private key")
        return key

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


def key_id(private_key: rsa.RSAPrivateKey) -> str:
    der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return b64url(hashlib.sha256(der).digest()[:12])


def public_jwk(private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()

    def encode_int(value: int) -> str:
        return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": key_id(private_key),
        "n": encode_int(numbers.n),
        "e": encode_int(numbers.e),
    }


def sign_token(private_key: rsa.RSAPrivateKey, payload: dict[str, Any]) -> str:
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": key_id(private_key)},
    )


def decode_token(
    token: str,
    private_key: rsa.RSAPrivateKey,
    issuer: str,
    audience: str | None = None,
) -> dict[str, Any]:
    options = {"verify_aud": audience is not None}
    return jwt.decode(
        token,
        private_key.public_key(),
        algorithms=["RS256"],
        issuer=issuer,
        audience=audience,
        options=options,
    )


def make_access_token(
    private_key: rsa.RSAPrivateKey,
    *,
    issuer: str,
    user_id: int,
    client_id: str,
    scopes: str,
    ttl_seconds: int,
) -> tuple[str, int]:
    now = utcnow()
    expires_at = now + timedelta(seconds=ttl_seconds)
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": str(user_id),
        "aud": client_id,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "scope": scopes,
        "token_use": "access",
        "client_id": client_id,
    }
    return sign_token(private_key, payload), int(expires_at.timestamp())


def make_id_token(
    private_key: rsa.RSAPrivateKey,
    *,
    issuer: str,
    user_id: int,
    client_id: str,
    name: str,
    email: str,
    email_verified: bool,
    scopes: list[str],
    ttl_seconds: int,
    nonce: str | None = None,
) -> str:
    now = utcnow()
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": str(user_id),
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "auth_time": int(now.timestamp()),
    }
    if nonce:
        payload["nonce"] = nonce
    if "profile" in scopes:
        payload["name"] = name
        payload["preferred_username"] = email.split("@")[0]
    if "email" in scopes:
        payload["email"] = email
        payload["email_verified"] = email_verified
    return sign_token(private_key, payload)


def verify_pkce(verifier: str | None, challenge: str, method: str) -> bool:
    if not challenge:
        return True
    if not verifier:
        return False
    if method.upper() == "S256":
        computed = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    elif method in ("", "plain"):
        computed = verifier
    else:
        return False
    return hmac.compare_digest(computed, challenge)
