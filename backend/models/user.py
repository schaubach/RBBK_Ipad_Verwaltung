"""User-related Pydantic models."""

import uuid
from datetime import UTC, datetime
from typing import Optional

from pydantic import BaseModel, Field


class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: str = "user"  # "admin" or "user"
    is_active: bool = True
    force_password_change: bool = False
    comment: Optional[str] = None
    department_id: Optional[str] = None  # Verweis auf departments.id, None = keine Abteilung
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class UserLogin(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"
    comment: Optional[str] = None
    department_id: Optional[str] = None


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    # Leerer Text loescht den Kommentar, leere Abteilung entfernt die Zuordnung. Deshalb
    # unterscheidet die Route zwischen "nicht mitgeschickt" (None) und "ausdruecklich leer".
    comment: Optional[str] = None
    department_id: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    is_active: bool
    force_password_change: bool = False
    comment: Optional[str] = None
    department_id: Optional[str] = None
    department_name: Optional[str] = None  # aufgeloest, damit die Oberflaeche nicht nachladen muss
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    force_password_change: bool = False
