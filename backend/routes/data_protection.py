"""Data protection / cleanup (/api/data-protection/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""
import io
import json
import os
import random
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pandas as pd
import PyPDF2
import xlsxwriter
from fastapi import Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from starlette.requests import Request

from core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    MAX_CONTRACTS_PER_STUDENT,
    MAX_IPADS_PER_STUDENT,
    db,
    limiter,
)
from core.mongo import parse_from_mongo, prepare_for_mongo
from core.router import api_router
from core.security import (
    create_access_token,
    get_current_user,
    get_ipad_filter_with_pool,
    get_password_hash,
    get_user_filter,
    is_admin,
    require_admin,
    validate_resource_ownership,
    verify_password,
)
from core.validators import is_contract_validated, sanitize_input, validate_uploaded_file
from models.assignment import (
    Assignment,
    AssignmentResponse,
    ManualAssignmentRequest,
    UploadResponse,
)
from models.contract import AssignmentHistory, Contract
from models.ipad import iPad
from models.student import Student, StudentWithAssignmentCount
from models.user import (
    LoginResponse,
    User,
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
)

@api_router.post("/data-protection/cleanup-old-data")
async def cleanup_old_data(current_user: dict = Depends(get_current_user)):
    """Delete students and contracts older than 5 years"""
    try:
        five_years_ago = datetime.now(timezone.utc) - timedelta(days=5*365)
        
        # Add timestamps to existing records if missing
        await add_missing_timestamps()
        
        # Delete old students (but keep those with active assignments)
        active_student_ids = []
        active_assignments = await db.assignments.find({"is_active": True}).to_list(length=None)
        active_student_ids = [a["student_id"] for a in active_assignments]
        
        old_students_result = await db.students.delete_many({
            "created_at": {"$lt": five_years_ago.isoformat()},
            "id": {"$nin": active_student_ids}
        })
        
        # Delete old contracts
        old_contracts_result = await db.contracts.delete_many({
            "uploaded_at": {"$lt": five_years_ago.isoformat()}
        })
        
        return {
            "message": "Data protection cleanup completed",
            "deleted_students": old_students_result.deleted_count,
            "deleted_contracts": old_contracts_result.deleted_count,
            "cutoff_date": five_years_ago.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during cleanup: {str(e)}")

async def add_missing_timestamps():
    """Add created_at timestamps to records that don't have them"""
    try:
        # Update students without created_at
        await db.students.update_many(
            {"created_at": {"$exists": False}},
            {"$set": {"created_at": datetime.now(timezone.utc).isoformat()}}
        )
        
        # Update contracts without uploaded_at
        await db.contracts.update_many(
            {"uploaded_at": {"$exists": False}},
            {"$set": {"uploaded_at": datetime.now(timezone.utc).isoformat()}}
        )
        
        # Update iPads without created_at
        await db.ipads.update_many(
            {"created_at": {"$exists": False}},
            {"$set": {"created_at": datetime.now(timezone.utc).isoformat()}}
        )
        
        # Update assignments without assigned_at
        await db.assignments.update_many(
            {"assigned_at": {"$exists": False}},
            {"$set": {"assigned_at": datetime.now(timezone.utc).isoformat()}}
        )
        
    except Exception as e:
        print(f"Error adding missing timestamps: {e}")

