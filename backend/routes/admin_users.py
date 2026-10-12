"""Admin user-management routes (/api/admin/users/*, cleanup)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import random
from datetime import UTC, datetime
from typing import List

from fastapi import Depends, HTTPException
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request

from core.config import (
    db,
    limiter,
)
from core.mongo import prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_password_hash,
    require_admin,
)
from models.user import (
    User,
    UserCreate,
    UserResponse,
    UserUpdate,
)


# Admin User Management Endpoints
def _parse_dt(value, fallback=None):
    """Mongo liefert Zeitstempel je nach Schreibweg als Text oder als datetime."""
    if value is None:
        return fallback
    return datetime.fromisoformat(value) if isinstance(value, str) else value


# Ersatzdatum fuer Konten ohne Zeitstempel. UserResponse verlangt ein datetime, None geht also
# nicht; der 1.1.1970 ist als Platzhalter erkennbar und erfindet kein plausibles Anlegedatum.
OHNE_ZEITSTEMPEL = datetime.fromtimestamp(0, UTC)


async def _user_response(user: dict, bg_namen: dict = None, zust: dict = None) -> UserResponse:
    """UserResponse aus einem Mongo-Dokument, mit den DERZEIT zustaendigen Bildungsgaengen.

    ``bg_namen`` und ``zust`` erlauben dem Listenendpunkt, Namen und Zustaendigkeiten einmal
    vorab zu laden, statt pro Benutzer zwei eigene Abfragen abzusetzen.
    """
    if zust is None:
        ids = [
            z["bildungsgang_id"]
            async for z in db.zustaendigkeiten.find({"user_id": user["id"], "bis": None}, {"bildungsgang_id": 1})
        ]
    else:
        ids = zust.get(user["id"], [])
    if bg_namen is None:
        bg_namen = {
            b["id"]: b["name"] async for b in db.bildungsgaenge.find({"id": {"$in": ids}}, {"id": 1, "name": 1})
        }
    # Altbestaende und aus Sicherungen zurueckgespielte Konten haben nicht zwingend ein
    # created_at. Ein hartes user["created_at"] liesse ein einziges solches Dokument die ganze
    # Benutzerliste abbrechen - der Admin kaeme dann an kein Konto mehr heran, auch nicht an
    # die unbeschaedigten, und koennte das kaputte erst recht nicht loeschen.
    angelegt = _parse_dt(user.get("created_at"), _parse_dt(user.get("updated_at"), OHNE_ZEITSTEMPEL))
    return UserResponse(
        id=user["id"],
        username=user["username"],
        role=user.get("role", "user"),
        is_active=user.get("is_active", True),
        force_password_change=user.get("force_password_change", False),
        comment=user.get("comment"),
        bildungsgaenge=[{"id": i, "name": bg_namen.get(i, "(unbekannt)")} for i in ids],
        created_by=user.get("created_by"),
        created_at=angelegt,
        updated_at=_parse_dt(user.get("updated_at"), angelegt),
    )


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
        comment=(user_data.comment or "").strip() or None,
        created_by=current_user["id"],
    )

    user_dict = prepare_for_mongo(new_user.dict())
    try:
        await db.users.insert_one(user_dict)
    except DuplicateKeyError:
        # Zwischen der Pruefung weiter oben und hier kann ein zweiter Aufruf denselben Namen
        # angelegt haben. Seit username_eindeutig (siehe main.py) faengt die Datenbank das ab -
        # der Aufrufer soll aber dieselbe Meldung sehen wie bei der Pruefung, nicht einen
        # Serverfehler mit rohem Mongo-Text.
        raise HTTPException(status_code=400, detail="Username already exists")

    # Return user response without password_hash
    return await _user_response(await db.users.find_one({"id": new_user.id}))


@api_router.get("/admin/users", response_model=List[UserResponse])
@limiter.limit("30/minute")
async def list_users(request: Request, current_user: dict = Depends(get_current_user)):
    """List all users (admin only)"""
    require_admin(current_user)

    users = await db.users.find().to_list(length=None)
    # Namen und laufende Zustaendigkeiten einmal laden statt zweimal pro Benutzer
    bg_namen = {b["id"]: b["name"] for b in await db.bildungsgaenge.find({}, {"id": 1, "name": 1}).to_list(length=None)}
    zust = {}
    for z in await db.zustaendigkeiten.find({"bis": None}, {"user_id": 1, "bildungsgang_id": 1}).to_list(length=None):
        zust.setdefault(z["user_id"], []).append(z["bildungsgang_id"])
    return [await _user_response(user, bg_namen, zust) for user in users]


@api_router.put("/admin/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: str, user_data: UserUpdate, current_user: dict = Depends(get_current_user)):
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
    update_dict = {"updated_at": datetime.now(UTC).isoformat()}

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

    # Kommentar: ein mitgeschickter Leerstring loescht ihn, ein fehlendes Feld laesst ihn stehen.
    if user_data.comment is not None:
        update_dict["comment"] = user_data.comment.strip() or None

    # Update user
    await db.users.update_one({"id": user_id}, {"$set": update_dict})

    return await _user_response(await db.users.find_one({"id": user_id}))


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
        {"id": user_id}, {"$set": {"is_active": False, "updated_at": datetime.now(UTC).isoformat()}}
    )

    # Count user's resources
    ipads_count = await db.ipads.count_documents({"user_id": user_id})
    students_count = await db.students.count_documents({"user_id": user_id})
    assignments_count = await db.assignments.count_documents({"user_id": user_id})

    return {
        "message": f"User {target_user['username']} has been deactivated",
        "user_id": user_id,
        "resources_preserved": {"ipads": ipads_count, "students": students_count, "assignments": assignments_count},
        "note": "User data has been preserved. To permanently delete data, use data management tools.",
    }


@api_router.delete("/admin/users/{user_id}/complete")
async def delete_user_complete(user_id: str, current_user: dict = Depends(get_current_user)):
    """Benutzerkonto endgültig entfernen (nur Admin).

    Loescht NUR das Konto. Geraete, Schueler, Zuordnungen und Vertraege gehoeren dem
    Bildungsgang, nicht der Person - sie bleiben und sind fuer die kuenftig Zustaendigen
    unveraendert erreichbar.

    Vorher loeschte dieser Endpunkt alles, was die Person je angelegt hatte. Beim Ausscheiden
    einer Kollegin verschwand damit der halbe Geraetebestand eines Bildungsgangs mitsamt
    Schuelerdaten und Vertrags-PDFs, die es nirgends sonst gibt. Genau dagegen ist der ganze
    Umbau gerichtet; hier waere er sonst wirkungslos.

    Laufende Zustaendigkeiten werden beendet, nicht geloescht - der Zugriff endet sofort,
    die Historie bleibt nachvollziehbar.
    """
    require_admin(current_user)

    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    # Was diese Person angelegt hat - bleibt erhalten, wird nur berichtet.
    erstellt = {
        "ipads": await db.ipads.count_documents({"user_id": user_id}),
        "students": await db.students.count_documents({"user_id": user_id}),
        "assignments": await db.assignments.count_documents({"user_id": user_id}),
        "contracts": await db.contracts.count_documents({"user_id": user_id}),
    }

    # Laufende Zustaendigkeiten beenden statt loeschen
    jetzt = datetime.now(UTC).isoformat()
    beendet = await db.zustaendigkeiten.update_many({"user_id": user_id, "bis": None}, {"$set": {"bis": jetzt}})

    await db.users.delete_one({"id": user_id})

    return {
        "message": f"Benutzerkonto '{target_user['username']}' wurde gelöscht.",
        "zustaendigkeiten_beendet": beendet.modified_count,
        "daten_erhalten": erstellt,
        "hinweis": "Von dieser Person angelegte Datensätze bleiben bei ihrem Bildungsgang erhalten.",
    }


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
        raise HTTPException(
            status_code=400, detail="Cannot reset your own password. Use the regular password change function."
        )

    # Generate 8-digit temporary password (only numbers)
    temp_password = "".join([str(random.randint(0, 9)) for _ in range(8)])

    # Hash the temporary password
    hashed_temp_password = get_password_hash(temp_password)

    # Update user with temporary password and set force_password_change flag
    await db.users.update_one(
        {"id": user_id},
        {
            "$set": {
                "password_hash": hashed_temp_password,
                "force_password_change": True,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        },
    )

    return {
        "message": f"Password for user '{target_user['username']}' has been reset",
        "username": target_user["username"],
        "temporary_password": temp_password,
        "note": "The user must change this password on next login. This temporary password will only be displayed once.",
    }
