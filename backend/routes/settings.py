"""Global settings (/api/settings/*)

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

# Global Settings endpoints
@api_router.get("/settings/global")
async def get_global_settings(current_user: dict = Depends(get_current_user)):
    """Get global application settings"""
    try:
        settings = await db.global_settings.find_one({"type": "app_settings"})
        if not settings:
            # Create default settings if they don't exist
            default_settings = {
                "type": "app_settings",
                "ipad_typ": "Apple iPad",
                "pencil": "ohne Apple Pencil",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            await db.global_settings.insert_one(default_settings)
            settings = default_settings
        
        return {
            "ipad_typ": settings.get("ipad_typ", "Apple iPad"),
            "pencil": settings.get("pencil", "ohne Apple Pencil")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting settings: {str(e)}")

@api_router.put("/settings/global")
async def update_global_settings(
    settings: dict,
    current_user: dict = Depends(get_current_user)
):
    """Update global application settings (Admin only)"""
    require_admin(current_user)
    try:
        ipad_typ = settings.get("ipad_typ", "Apple iPad")
        pencil = settings.get("pencil", "ohne Apple Pencil")
        
        update_data = {
            "ipad_typ": ipad_typ,
            "pencil": pencil,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        result = await db.global_settings.update_one(
            {"type": "app_settings"},
            {"$set": update_data},
            upsert=True
        )
        
        return {
            "message": "Einstellungen erfolgreich aktualisiert",
            "ipad_typ": ipad_typ,
            "pencil": pencil
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating settings: {str(e)}")

