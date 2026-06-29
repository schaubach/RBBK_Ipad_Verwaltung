"""Assignment models."""
from datetime import datetime, timezone
from typing import List, Optional
import uuid

from pydantic import BaseModel, Field


class Assignment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    student_id: str
    ipad_id: str
    itnr: str
    student_name: str
    is_active: bool = True
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    unassigned_at: Optional[datetime] = None
    contract_id: Optional[str] = None
    contract_warning: Optional[bool] = False
    warning_dismissed: Optional[bool] = False


class ManualAssignmentRequest(BaseModel):
    student_id: str
    ipad_id: str


class AssignmentResponse(BaseModel):
    message: str
    assigned_count: int
    details: List[str]


class UploadResponse(BaseModel):
    message: str
    processed_count: int
    skipped_count: int
    details: List[str]
