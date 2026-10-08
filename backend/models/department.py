"""Department model.

Abteilungen sind eine eigene Sammlung mit festen IDs, nicht ein Freitextfeld am Benutzer.
Das kostet hier etwas mehr, haelt aber den Weg offen, spaeter auch Geraete einer Abteilung
zuzuordnen - dafuer braucht es eine stabile Kennung, die ein Umbenennen uebersteht.
"""

import uuid
from datetime import UTC, datetime
from typing import Optional

from pydantic import BaseModel, Field


class Department(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DepartmentCreate(BaseModel):
    name: str
    description: Optional[str] = None


class DepartmentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class DepartmentResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    user_count: int = 0
    created_at: datetime
    updated_at: datetime
