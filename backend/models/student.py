"""Student models."""

import uuid
from datetime import UTC, datetime
from typing import Optional

from pydantic import BaseModel, Field


class Student(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    sname: Optional[str] = None
    sus_nachn: str
    sus_vorn: str
    sus_kl: Optional[str] = None
    sus_str_hnr: Optional[str] = None
    sus_plz: Optional[str] = None
    sus_ort: Optional[str] = None
    sus_geb: Optional[str] = None
    erz1_nachn: Optional[str] = None
    erz1_vorn: Optional[str] = None
    erz1_str_hnr: Optional[str] = None
    erz1_plz: Optional[str] = None
    erz1_ort: Optional[str] = None
    erz2_nachn: Optional[str] = None
    erz2_vorn: Optional[str] = None
    erz2_str_hnr: Optional[str] = None
    erz2_plz: Optional[str] = None
    erz2_ort: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class StudentWithAssignmentCount(Student):
    assignment_count: int = 0
