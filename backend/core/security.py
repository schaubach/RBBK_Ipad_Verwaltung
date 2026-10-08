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


# Endpoints that must stay reachable for a user whose password change is still pending -
# otherwise they could never clear the flag (or even log out). Everything else is blocked
# server-side until they change their password; previously this was only enforced by the
# frontend's Login.jsx dialog, so a temporary password could be used against the API directly.
_FORCE_PASSWORD_CHANGE_ALLOWED_PATHS = {
    "/api/auth/change-password-forced",
    "/api/auth/logout",
    "/api/auth/me",
}


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
        if user.get("force_password_change") and request.url.path not in _FORCE_PASSWORD_CHANGE_ALLOWED_PATHS:
            raise HTTPException(
                status_code=403, detail="Passwort muss zuerst geändert werden (PUT /auth/change-password-forced)."
            )
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


async def require_admin_user(current_user: dict = Depends(get_current_user)) -> dict:
    """Dependency for routes that are admin-only in their entirety (unlike routes where only
    part of the behavior is admin-gated, e.g. create_ipad's is_in_pool flag - those keep an
    inline require_admin/is_admin check instead). Declaring this as the route's user dependency
    makes admin-only-ness visible in the function signature and enforced before the body runs,
    instead of relying on every handler remembering to call require_admin() as its first line."""
    require_admin(current_user)
    return current_user


async def get_responsible_bildungsgang_ids(user: dict) -> list:
    """Die Bildungsgänge, für die diese Person DERZEIT zuständig ist (bis is None).

    Einzige Stelle, an der aus Zuständigkeits-Datensätzen Zugriff wird. Endet eine
    Zuständigkeit, endet damit der Zugriff - die Daten bleiben beim Bildungsgang.
    """
    cursor = db.zustaendigkeiten.find({"user_id": user["id"], "bis": None}, {"bildungsgang_id": 1})
    return [z["bildungsgang_id"] async for z in cursor]


async def get_user_filter(user: dict) -> dict:
    """MongoDB filter scoping queries to the caller's Bildungsgänge (admin = unfiltered).

    Wer für nichts zuständig ist, bekommt einen Filter, der NICHTS trifft - nicht etwa einen
    leeren Filter, der alles träfe. Das ist der Unterschied zwischen "sieht nichts" und
    "sieht alles", und er hängt an einer einzigen Zeile.
    """
    if is_admin(user):
        return {}
    return {"bildungsgang_id": {"$in": await get_responsible_bildungsgang_ids(user)}}


async def get_ipad_filter(user: dict) -> dict:
    """iPad filter: admins see everything (incl. pool); regular users see only the non-pool
    iPads of the Bildungsgänge they are currently responsible for.

    Die is_in_pool-Klausel ist nicht kosmetisch: ein in den Pool gegebenes Gerät behält seinen
    bildungsgang_id (siehe release_ipad_to_pool). Ohne diese Klausel taucht jedes je in den Pool
    gegebene Gerät wieder im Bestand des Bildungsgangs auf und liesse sich dort ausgeben,
    obwohl die zentrale Verwaltung es als Poolbestand führt.
    """
    if is_admin(user):
        return {}
    return {
        "bildungsgang_id": {"$in": await get_responsible_bildungsgang_ids(user)},
        "is_in_pool": {"$ne": True},
    }


async def resolve_bildungsgang(user: dict, explicit_id: Optional[str] = None) -> str:
    """Bestimmt, welchem Bildungsgang ein NEUER Datensatz gehört.

    Drei Fälle, und der mittlere ist der Alltag:
    - ausdrücklich angegeben: wird übernommen, sofern die Person dort schreiben darf
    - für genau einen zuständig: der wird genommen, ohne Rückfrage
    - für mehrere zuständig (oder Admin): muss gewählt werden

    Admins bekommen bewusst keine Vorauswahl. Sie sind für nichts zuständig und für alles
    zuständig zugleich - eine geratene Zuordnung landete unbemerkt im falschen Bestand.
    Genau so sind die 105 Geräte am admin-Konto entstanden.
    """
    verfuegbar = await get_responsible_bildungsgang_ids(user)

    if explicit_id:
        if is_admin(user) or explicit_id in verfuegbar:
            if not await db.bildungsgaenge.find_one({"id": explicit_id}):
                raise HTTPException(status_code=400, detail="Der gewählte Bildungsgang existiert nicht.")
            return explicit_id
        raise HTTPException(status_code=403, detail="Für diesen Bildungsgang sind Sie nicht zuständig.")

    # Die Zustaendigkeit bestimmt die Vorauswahl - fuer alle gleich. Admin-Sein erweitert nur,
    # wohin geschrieben werden DARF, es ist keine Ausnahme von dieser Regel. Ein Admin, der
    # genau einen Bildungsgang betreut, arbeitet damit so beiläufig wie jeder andere.
    if len(verfuegbar) == 1:
        return verfuegbar[0]

    if not verfuegbar:
        if is_admin(user):
            raise HTTPException(
                status_code=400,
                detail="Bitte einen Bildungsgang auswählen. Dieses Konto betreut selbst keinen, "
                "deshalb gibt es keine Vorauswahl - damit nichts versehentlich im falschen Bestand landet.",
            )
        raise HTTPException(
            status_code=400,
            detail="Sie sind derzeit für keinen Bildungsgang zuständig und können deshalb nichts anlegen. "
            "Bitte an die Administration wenden.",
        )

    namen = [
        b["name"] async for b in db.bildungsgaenge.find({"id": {"$in": verfuegbar}}, {"name": 1}).sort("name", 1)
    ]
    raise HTTPException(
        status_code=400,
        detail="Bitte einen Bildungsgang auswählen: " + ", ".join(namen),
    )


async def validate_resource_ownership(resource_type: str, resource_id: str, user: dict):
    """Ensure user owns the resource (admin bypasses; pool iPads are admin-only, see get_ipad_filter)."""
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

    # Zugehörigkeit prüfen, nicht Urheberschaft: user_id trägt nur noch "angelegt von".
    if resource.get("bildungsgang_id") not in await get_responsible_bildungsgang_ids(user):
        raise HTTPException(status_code=403, detail="Access denied to this resource")

    return True
