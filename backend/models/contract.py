"""Contract models."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from models.assignment import Assignment


class Contract(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    assignment_id: Optional[str] = None
    ipad_id: Optional[str] = None
    student_id: Optional[str] = None
    itnr: Optional[str] = None
    student_name: Optional[str] = None
    filename: str
    file_data: bytes
    form_fields: Dict[str, Any]
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class AssignmentHistory(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ipad_id: str
    itnr: str
    assignments: List[Assignment]
    contracts: List[Contract]
