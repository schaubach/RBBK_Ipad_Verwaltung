"""iPad model."""

import uuid
from datetime import UTC, datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class iPad(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: Optional[str] = None  # Owner (None = orphan in pool)
    itnr: str
    snr: str
    karton: Optional[str] = None
    pencil: Optional[str] = None
    typ: Optional[str] = None
    modell: Optional[str] = None
    ansch_jahr: Optional[str] = None
    ausleihe_datum: Optional[str] = None
    status: str = "ok"  # ok, defekt, gestohlen
    current_assignment_id: Optional[str] = None
    is_in_pool: bool = False
    pool_history: List[dict] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
