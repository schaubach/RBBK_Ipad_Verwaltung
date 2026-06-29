"""Admin user-management routes (/api/admin/users/*, cleanup)

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

# Admin User Management Endpoints
@api_router.post("/admin/users", response_model=UserResponse)
async def create_user(user_data: UserCreate, current_user: dict = Depends(get_current_user)):
    """Create a new user (admin only)"""
    require_admin(current_user)
    
    # Validate username
    if len(user_data.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
    
    # Check if username already exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Validate password
    if len(user_data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
    
    # Validate role
    if user_data.role not in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        password_hash=hashed_password,
        role=user_data.role,
        is_active=True,
        created_by=current_user["id"]
    )
    
    user_dict = prepare_for_mongo(new_user.dict())
    await db.users.insert_one(user_dict)
    
    # Return user response without password_hash
    return UserResponse(
        id=new_user.id,
        username=new_user.username,
        role=new_user.role,
        is_active=new_user.is_active,
        force_password_change=new_user.force_password_change,
        created_by=new_user.created_by,
        created_at=new_user.created_at,
        updated_at=new_user.updated_at
    )

@api_router.get("/admin/users", response_model=List[UserResponse])
@limiter.limit("30/minute")
async def list_users(request: Request, current_user: dict = Depends(get_current_user)):
    """List all users (admin only)"""
    require_admin(current_user)
    
    users = await db.users.find().to_list(length=None)
    
    return [
        UserResponse(
            id=user["id"],
            username=user["username"],
            role=user.get("role", "user"),
            is_active=user.get("is_active", True),
            force_password_change=user.get("force_password_change", False),
            created_by=user.get("created_by"),
            created_at=datetime.fromisoformat(user["created_at"]) if isinstance(user["created_at"], str) else user["created_at"],
            updated_at=datetime.fromisoformat(user["updated_at"]) if isinstance(user.get("updated_at"), str) else user.get("updated_at", user["created_at"])
        )
        for user in users
    ]

@api_router.put("/admin/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str, 
    user_data: UserUpdate, 
    current_user: dict = Depends(get_current_user)
):
    """Update a user (admin only)"""
    require_admin(current_user)
    
    # Get user to update
    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deactivation
    if user_id == current_user["id"] and user_data.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    
    # Build update dict
    update_dict = {"updated_at": datetime.now(timezone.utc).isoformat()}
    
    if user_data.password:
        if len(user_data.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")
        update_dict["password_hash"] = get_password_hash(user_data.password)
    
    if user_data.role:
        if user_data.role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="Role must be 'admin' or 'user'")
        update_dict["role"] = user_data.role
    
    if user_data.is_active is not None:
        update_dict["is_active"] = user_data.is_active
    
    # Update user
    await db.users.update_one(
        {"id": user_id},
        {"$set": update_dict}
    )
    
    # Get updated user
    updated_user = await db.users.find_one({"id": user_id})
    
    return UserResponse(
        id=updated_user["id"],
        username=updated_user["username"],
        role=updated_user.get("role", "user"),
        is_active=updated_user.get("is_active", True),
        force_password_change=updated_user.get("force_password_change", False),
        created_by=updated_user.get("created_by"),
        created_at=datetime.fromisoformat(updated_user["created_at"]) if isinstance(updated_user["created_at"], str) else updated_user["created_at"],
        updated_at=datetime.fromisoformat(updated_user["updated_at"]) if isinstance(updated_user.get("updated_at"), str) else updated_user.get("updated_at", updated_user["created_at"])
    )

@api_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a user (admin only) - NOTE: This will NOT delete user's data, just deactivate the account"""
    require_admin(current_user)
    
    # Get user to delete
    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deletion
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Instead of deleting, deactivate the user
    # This preserves data integrity and allows potential reactivation
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "is_active": False,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    # Count user's resources
    ipads_count = await db.ipads.count_documents({"user_id": user_id})
    students_count = await db.students.count_documents({"user_id": user_id})
    assignments_count = await db.assignments.count_documents({"user_id": user_id})
    
    return {
        "message": f"User {target_user['username']} has been deactivated",
        "user_id": user_id,
        "resources_preserved": {
            "ipads": ipads_count,
            "students": students_count,
            "assignments": assignments_count
        },
        "note": "User data has been preserved. To permanently delete data, use data management tools."
    }


@api_router.delete("/admin/users/{user_id}/complete")
async def delete_user_complete(user_id: str, current_user: dict = Depends(get_current_user)):
    """
    PERMANENTLY delete a user and ALL their data (admin only)
    WARNING: This action is IRREVERSIBLE!
    Deletes: User account, iPads, Students, Assignments, Contracts
    """
    require_admin(current_user)
    
    # Get user to delete
    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-deletion
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Count resources before deletion
    ipads_count = await db.ipads.count_documents({"user_id": user_id, "is_in_pool": False})
    pool_ipads_count = await db.ipads.count_documents({"user_id": user_id, "is_in_pool": True})
    students_count = await db.students.count_documents({"user_id": user_id})
    assignments_count = await db.assignments.count_documents({"user_id": user_id})
    contracts_count = await db.contracts.count_documents({"user_id": user_id})
    
    # Cascading delete: Delete all user's data
    try:
        # Delete assignments first (references iPads and Students)
        await db.assignments.delete_many({"user_id": user_id})
        
        # Delete contracts
        await db.contracts.delete_many({"user_id": user_id})
        
        # Delete iPads owned by user (NOT in pool)
        await db.ipads.delete_many({"user_id": user_id, "is_in_pool": False})
        
        # Pool iPads imported by this user: release ownership (keep in pool, user_id=null)
        if pool_ipads_count > 0:
            await db.ipads.update_many(
                {"user_id": user_id, "is_in_pool": True},
                {"$set": {"user_id": None, "updated_at": datetime.now(timezone.utc).isoformat()}}
            )
        
        # Delete students
        await db.students.delete_many({"user_id": user_id})
        
        # Finally, delete the user account
        await db.users.delete_one({"id": user_id})
        
        return {
            "message": f"User '{target_user['username']}' and all associated data have been permanently deleted",
            "deleted_user_id": user_id,
            "deleted_username": target_user["username"],
            "deleted_resources": {
                "ipads": ipads_count,
                "pool_ipads_orphaned": pool_ipads_count,
                "students": students_count,
                "assignments": assignments_count,
                "contracts": contracts_count
            },
            "warning": "This action was IRREVERSIBLE. All data has been permanently removed."
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error during deletion process: {str(e)}. Some data may have been partially deleted."
        )


@api_router.post("/admin/cleanup-orphaned-data")
async def cleanup_orphaned_data(current_user: dict = Depends(get_current_user)):
    """
    Cleanup orphaned data (iPads, Students, etc.) from deleted users (admin only)
    This removes data that belongs to non-existent users
    """
    require_admin(current_user)
    
    try:
        # Get all existing user IDs
        existing_users = await db.users.find({}, {"id": 1}).to_list(length=None)
        existing_user_ids = {user["id"] for user in existing_users}
        
        # Find orphaned iPads
        all_ipads = await db.ipads.find({}, {"id": 1, "user_id": 1, "itnr": 1}).to_list(length=None)
        orphaned_ipads = [ipad for ipad in all_ipads if ipad["user_id"] not in existing_user_ids]
        orphaned_ipad_ids = [ipad["id"] for ipad in orphaned_ipads]
        
        # Find orphaned Students
        all_students = await db.students.find({}, {"id": 1, "user_id": 1}).to_list(length=None)
        orphaned_students = [s for s in all_students if s["user_id"] not in existing_user_ids]
        orphaned_student_ids = [s["id"] for s in orphaned_students]
        
        # Find orphaned Assignments
        all_assignments = await db.assignments.find({}, {"id": 1, "user_id": 1}).to_list(length=None)
        orphaned_assignments = [a for a in all_assignments if a["user_id"] not in existing_user_ids]
        
        # Find orphaned Contracts
        all_contracts = await db.contracts.find({}, {"id": 1, "user_id": 1}).to_list(length=None)
        orphaned_contracts = [c for c in all_contracts if c["user_id"] not in existing_user_ids]
        
        # Delete orphaned data
        deleted_ipads = await db.ipads.delete_many({"id": {"$in": orphaned_ipad_ids}})
        deleted_students = await db.students.delete_many({"id": {"$in": orphaned_student_ids}})
        deleted_assignments = await db.assignments.delete_many({"user_id": {"$nin": list(existing_user_ids)}})
        deleted_contracts = await db.contracts.delete_many({"user_id": {"$nin": list(existing_user_ids)}})
        
        return {
            "message": "Orphaned data cleanup completed",
            "deleted_resources": {
                "ipads": deleted_ipads.deleted_count,
                "students": deleted_students.deleted_count,
                "assignments": deleted_assignments.deleted_count,
                "contracts": deleted_contracts.deleted_count
            },
            "details": {
                "orphaned_ipad_itnrs": [ipad["itnr"] for ipad in orphaned_ipads[:10]],  # Show first 10
                "total_orphaned_ipads": len(orphaned_ipads)
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error during cleanup: {str(e)}"
        )


@api_router.post("/admin/users/{user_id}/reset-password")
async def reset_user_password(user_id: str, current_user: dict = Depends(get_current_user)):
    """Reset user password to a temporary 8-digit code (admin only)"""
    require_admin(current_user)
    
    # Get user to reset
    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent self-reset (admins should use regular password change)
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot reset your own password. Use the regular password change function.")
    
    # Generate 8-digit temporary password (only numbers)
    import random
    temp_password = ''.join([str(random.randint(0, 9)) for _ in range(8)])
    
    # Hash the temporary password
    hashed_temp_password = get_password_hash(temp_password)
    
    # Update user with temporary password and set force_password_change flag
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "password_hash": hashed_temp_password,
            "force_password_change": True,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {
        "message": f"Password for user '{target_user['username']}' has been reset",
        "username": target_user["username"],
        "temporary_password": temp_password,
        "note": "The user must change this password on next login. This temporary password will only be displayed once."
    }

