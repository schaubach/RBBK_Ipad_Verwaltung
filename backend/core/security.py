"""Authentication, JWT, RBAC and resource-ownership helpers."""

from datetime import UTC, datetime, timedelta
from typing import Optional

import jwt
from fastapi import Cookie, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from core.config import SECRET_KEY, db, pwd_context, security


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    to_encode.update({"user_id": user_id})
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    access_token: str = Cookie(default=None),
):
    """Resolve current user from JWT (HttpOnly cookie preferred, Bearer header fallback)."""
    token = None
    if access_token:
        token = access_token
    elif credentials:
        token = credentials.credentials

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        exp: int = payload.get("exp")

        if username is None or user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        if exp is None:
            raise HTTPException(status_code=401, detail="Token missing expiration")
        if datetime.now(UTC).timestamp() > exp:
            raise HTTPException(status_code=401, detail="Token has expired")

        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="User account is deactivated")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def is_admin(user: dict) -> bool:
    return user.get("role") == "admin"


def require_admin(user: dict):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin access required")


async def get_user_filter(user: dict) -> dict:
    """MongoDB filter scoping queries to the user's resources (admin = unfiltered)."""
    if is_admin(user):
        return {}
    return {"user_id": user["id"]}


async def get_ipad_filter_with_pool(user: dict) -> dict:
    """iPad filter that includes pool items visible to all users."""
    if is_admin(user):
        return {}
    return {"$or": [{"user_id": user["id"]}, {"is_in_pool": True}]}


async def validate_resource_ownership(resource_type: str, resource_id: str, user: dict):
    """Ensure user owns the resource (pool iPads bypass ownership)."""
    if is_admin(user):
        return True

    collection_map = {
        "ipad": db.ipads,
        "student": db.students,
        "assignment": db.assignments,
        "contract": db.contracts,
    }
    collection = collection_map.get(resource_type)
    if collection is None:
        raise HTTPException(status_code=400, detail=f"Invalid resource type: {resource_type}")

    resource = await collection.find_one({"id": resource_id})
    if not resource:
        raise HTTPException(status_code=404, detail=f"{resource_type.capitalize()} not found")

    if resource_type == "ipad" and resource.get("is_in_pool"):
        return True

    if resource.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied to this resource")

    return True
