"""Authentication routes (/api/auth/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

from datetime import UTC, datetime, timedelta

from core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    db,
    limiter,
)
from core.mongo import prepare_for_mongo
from core.router import api_router
from core.security import (
    create_access_token,
    get_current_user,
    get_password_hash,
    verify_password,
)
from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse
from models.user import (
    User,
    UserLogin,
)
from starlette.requests import Request


# Authentication endpoints
@api_router.post("/auth/setup", response_model=dict)
async def setup_admin():
    """Setup initial admin user - only creates if NO admin exists"""
    # Check if ANY admin user exists (not just username "admin")
    existing_admin = await db.users.find_one({"role": "admin"})
    if existing_admin:
        return {"message": "Admin user already exists"}

    # Check if old-style admin exists (without role field)
    legacy_admin = await db.users.find_one({"username": "admin"})
    if legacy_admin:
        # Update legacy admin to have admin role
        await db.users.update_one({"username": "admin"}, {"$set": {"role": "admin", "is_active": True}})
        return {"message": "Admin user updated with role"}

    # No admin exists - create default admin
    hashed_password = get_password_hash("admin123")
    user = User(username="admin", password_hash=hashed_password, role="admin", is_active=True)
    user_dict = prepare_for_mongo(user.dict())
    await db.users.insert_one(user_dict)
    return {"message": "Admin user created successfully", "username": "admin", "password": "admin123"}


@api_router.put("/auth/change-password")
async def change_password(password_data: dict, current_user: dict = Depends(get_current_user)):
    """Change user password"""
    try:
        current_password = password_data.get("current_password")
        new_password = password_data.get("new_password")

        if not current_password or not new_password:
            raise HTTPException(status_code=400, detail="Current password and new password are required")

        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="New password must be at least 6 characters long")

        # Get current user from database (current_user is already the user dict)
        user = await db.users.find_one({"id": current_user["id"]})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify current password
        if not verify_password(current_password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        # Update password
        hashed_new_password = get_password_hash(new_password)
        await db.users.update_one(
            {"id": current_user["id"]},
            {"$set": {"password_hash": hashed_new_password, "updated_at": datetime.now(UTC).isoformat()}},
        )

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error changing password: {str(e)}")


@api_router.put("/auth/change-password-forced")
async def change_password_forced(password_data: dict, current_user: dict = Depends(get_current_user)):
    """Change password after forced reset (no current password required)"""
    try:
        new_password = password_data.get("new_password")

        if not new_password:
            raise HTTPException(status_code=400, detail="New password is required")

        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="New password must be at least 6 characters long")

        # Get current user from database
        user = await db.users.find_one({"id": current_user["id"]})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Update password and clear force_password_change flag
        hashed_new_password = get_password_hash(new_password)
        await db.users.update_one(
            {"id": current_user["id"]},
            {
                "$set": {
                    "password_hash": hashed_new_password,
                    "force_password_change": False,
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            },
        )

        return {"message": "Password changed successfully. You can now use your new password to login."}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error changing password: {str(e)}")


@api_router.post("/auth/login")
@limiter.limit("5/minute")  # Max 5 login attempts per minute
async def login(request: Request, user_data: UserLogin):
    user = await db.users.find_one({"username": user_data.username})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(status_code=401, detail="User account is deactivated")

    access_token = create_access_token(
        data={"sub": user_data.username},
        user_id=user["id"],
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    # Create response with HttpOnly cookie
    response = JSONResponse(
        content={
            "message": "Login successful",
            "access_token": access_token,  # Still return for backwards compatibility
            "token_type": "bearer",
            "role": user.get("role", "user"),
            "username": user["username"],
            "force_password_change": user.get("force_password_change", False),
        }
    )

    # Set HttpOnly cookie - JavaScript cannot access this!
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevents JavaScript access (XSS protection)
        secure=True,  # Only send over HTTPS
        samesite="strict",  # CSRF protection
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Cookie expiry matches token
        path="/api",  # Only sent to API routes
    )

    return response


@api_router.post("/auth/logout")
async def logout(request: Request):
    """Logout user by clearing the HttpOnly cookie"""
    response = JSONResponse(content={"message": "Logged out successfully"})
    response.delete_cookie(key="access_token", path="/api", httponly=True, secure=True, samesite="strict")
    return response


@api_router.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info (used to verify auth status)"""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "role": current_user.get("role", "user"),
        "is_active": current_user.get("is_active", True),
    }
