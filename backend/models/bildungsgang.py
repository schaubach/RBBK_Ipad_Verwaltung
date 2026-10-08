"""Bildungsgang model and responsibility periods.

Bildungsgänge sind eine eigene Sammlung mit festen IDs, keine Freitextangabe am Benutzer:
nur so übersteht eine Umbenennung alle Zuordnungen, und nur so können Geräte, Schüler und
Verträge an der Einheit hängen statt an einer Person.

Zuständigkeit ist bewusst ein eigener Datensatz mit Gültigkeitszeitraum und nicht ein Feld
am Bildungsgang. Ein Protokoll neben einem aktuellen Feld läuft früher oder später
auseinander - mit Zeiträumen ist "wer ist jetzt zuständig" dieselbe Abfrage wie "wer war im
März zuständig", nur mit anderem Datum. Eine Person kann mehrere Bildungsgänge betreuen und
ein Bildungsgang mehrere Zuständige haben.
"""

import uuid
from datetime import UTC, datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class Bildungsgang(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BildungsgangCreate(BaseModel):
    name: str
    description: Optional[str] = None


class BildungsgangUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class ZustaendigkeitPerson(BaseModel):
    """Eine Person in der Zuständigkeitsliste eines Bildungsgangs."""

    user_id: str
    username: str
    von: Optional[str] = None
    bis: Optional[str] = None  # None = derzeit zuständig


class BildungsgangResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    # Aufgelöst mitgeliefert, damit Listen und Auswahlfelder nicht nachladen müssen.
    zustaendige: List[ZustaendigkeitPerson] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class Zustaendigkeit(BaseModel):
    """Verantwortung einer Person für einen Bildungsgang in einem Zeitraum.

    ``bis is None`` bedeutet "derzeit zuständig" - genau daraus leitet sich der Zugriff ab.
    Ein Wechsel setzt ``bis`` am alten Datensatz und legt einen neuen an; gelöscht wird nichts,
    damit die Historie erhalten bleibt.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    bildungsgang_id: str
    user_id: str
    von: datetime = Field(default_factory=lambda: datetime.now(UTC))
    bis: Optional[datetime] = None
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ZustaendigkeitCreate(BaseModel):
    user_id: str
