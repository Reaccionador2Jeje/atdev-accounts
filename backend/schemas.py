from __future__ import annotations

import re
import sqlite3
from typing import Any

from pydantic import BaseModel, Field, field_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        raise ValueError("Enter a valid email address")
    return value


class UserOut(BaseModel):
    id: int
    name: str
    email: str
    email_verified: bool
    created_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "UserOut":
        return cls(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            email_verified=bool(row["email_verified"]),
            created_at=row["created_at"],
        )


class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str
    password: str = Field(min_length=8, max_length=256)
    remember: bool = False

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError("Name is required")
        return value

    @field_validator("email")
    @classmethod
    def clean_email(cls, value: str) -> str:
        return _validate_email(value)


class LoginIn(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=256)
    remember: bool = False

    @field_validator("email")
    @classmethod
    def clean_email(cls, value: str) -> str:
        return _validate_email(value)


class UpdateProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError("Name is required")
        return value


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class DeleteAccountIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class ApiKeyCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError("Name is required")
        return value


class ApiKeyOut(BaseModel):
    id: int
    name: str
    prefix: str
    created_at: str
    last_used_at: str | None = None


class ApiKeyCreated(ApiKeyOut):
    key: str


class SessionOut(BaseModel):
    id: int
    created_at: str
    last_seen_at: str
    expires_at: str
    user_agent: str
    ip: str
    current: bool


class ClientCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    redirect_uris: list[str] = Field(min_length=1)
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    public: bool = False
    client_secret: str | None = None

    @field_validator("redirect_uris")
    @classmethod
    def clean_redirects(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for uri in value:
            uri = uri.strip()
            if not uri.startswith(("http://", "https://")) and not uri.startswith("/"):
                raise ValueError("redirect_uris must be absolute http(s) URLs")
            cleaned.append(uri)
        if not cleaned:
            raise ValueError("At least one redirect URI is required")
        return cleaned


class ClientOut(BaseModel):
    client_id: str
    name: str
    redirect_uris: list[str]
    scopes: list[str]
    is_confidential: bool
    created_at: str


class ClientCreated(ClientOut):
    client_secret: str | None = None


def as_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}
