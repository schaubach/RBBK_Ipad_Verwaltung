"""iPad CRUD, pool and history routes (/api/ipads/*, /api/admin/ipads/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

from datetime import UTC, datetime
from typing import List, Optional

from core.config import (
    db,
    limiter,
)
from core.mongo import parse_from_mongo, prepare_for_mongo
from core.router import api_router
from core.security import (
    get_current_user,
    get_ipad_filter_with_pool,
    get_user_filter,
    is_admin,
    require_admin,
)
from fastapi import Depends, HTTPException
from models.assignment import (
    Assignment,
)
from models.ipad import iPad
from pydantic import BaseModel
from starlette.requests import Request

# iPad management endpoints


@api_router.post("/ipads", response_model=iPad)
async def create_ipad(ipad_data: dict, current_user: dict = Depends(get_current_user)):
    """Manuell ein neues iPad anlegen. Optional: is_in_pool=true für Pool-Anlage"""
    try:
        # Validate required fields
        if not ipad_data.get("itnr") or not ipad_data.get("snr"):
            raise HTTPException(status_code=400, detail="ITNr und SNr sind erforderlich")

        is_in_pool = bool(ipad_data.get("is_in_pool", False))

        # Pool: global uniqueness check; non-pool: per-user uniqueness
        if is_in_pool:
            existing = await db.ipads.find_one({"itnr": ipad_data["itnr"]})
            if existing:
                raise HTTPException(
                    status_code=400,
                    detail=f"iPad mit ITNr {ipad_data['itnr']} existiert bereits (Pool-Import erfordert globale Eindeutigkeit)",
                )
        else:
            existing = await db.ipads.find_one({"itnr": ipad_data["itnr"], "user_id": current_user["id"]})
            if existing:
                raise HTTPException(status_code=400, detail=f"iPad mit ITNr {ipad_data['itnr']} existiert bereits")

        # Create iPad object
        ipad = iPad(
            user_id=current_user["id"],
            itnr=ipad_data["itnr"],
            snr=ipad_data["snr"],
            karton=ipad_data.get("karton", ""),
            pencil=ipad_data.get("pencil", ""),
            typ=ipad_data.get("typ", ""),
            modell=ipad_data.get("modell") or None,
            ansch_jahr=ipad_data.get("ansch_jahr", ""),
            ausleihe_datum=ipad_data.get("ausleihe_datum", ""),
            status=ipad_data.get("status", "ok"),
            is_in_pool=is_in_pool,
            pool_history=[{"action": "imported_to_pool", "by": current_user["id"], "at": datetime.now(UTC).isoformat()}]
            if is_in_pool
            else [],
        )

        ipad_dict = prepare_for_mongo(ipad.dict())
        result = await db.ipads.insert_one(ipad_dict)

        # Fetch and return created iPad
        created_ipad = await db.ipads.find_one({"_id": result.inserted_id})
        return iPad(**parse_from_mongo(created_ipad))

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Anlegen: {str(e)}")


@api_router.get("/ipads", response_model=List[iPad])
@limiter.limit("60/minute")
async def get_ipads(request: Request, current_user: dict = Depends(get_current_user)):
    # Apply filter including pool iPads
    ipad_filter = await get_ipad_filter_with_pool(current_user)
    ipads = await db.ipads.find(ipad_filter).to_list(length=None)
    return [iPad(**parse_from_mongo(ipad)) for ipad in ipads]


@api_router.post("/ipads/{ipad_id}/claim")
@limiter.limit("60/minute")
async def claim_ipad_from_pool(ipad_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Claim an iPad from the shared pool into own inventory (atomic operation)."""
    now_iso = datetime.now(UTC).isoformat()

    # Atomic claim: only succeeds if iPad is still in pool
    result = await db.ipads.find_one_and_update(
        {"id": ipad_id, "is_in_pool": True},
        {
            "$set": {"is_in_pool": False, "user_id": current_user["id"], "updated_at": now_iso},
            "$push": {"pool_history": {"action": "claimed", "by": current_user["id"], "at": now_iso}},
        },
    )

    if not result:
        # Either iPad doesn't exist or was already claimed by someone else
        existing = await db.ipads.find_one({"id": ipad_id})
        if not existing:
            raise HTTPException(status_code=404, detail="iPad nicht gefunden")
        raise HTTPException(status_code=409, detail="iPad ist nicht (mehr) im Pool verfügbar")

    return {"message": f"iPad {result.get('itnr')} erfolgreich übernommen", "itnr": result.get("itnr")}


class BulkClaimRequest(BaseModel):
    ipad_ids: List[str]


class AdminAssignToUserRequest(BaseModel):
    ipad_ids: List[str]
    target_user_id: str


@api_router.post("/admin/ipads/assign-to-user")
@limiter.limit("30/minute")
async def admin_assign_ipads_to_user(
    payload: AdminAssignToUserRequest, request: Request, current_user: dict = Depends(get_current_user)
):
    """Admin-only: Assign one or more pool iPads to a specific user."""
    require_admin(current_user)

    if not payload.ipad_ids:
        raise HTTPException(status_code=400, detail="Keine iPads ausgewählt")

    # Verify target user exists
    target_user = await db.users.find_one({"id": payload.target_user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="Ziel-Benutzer nicht gefunden")

    now_iso = datetime.now(UTC).isoformat()
    success = []
    failed = []

    for ipad_id in payload.ipad_ids:
        # Atomic: only succeeds if iPad is still in pool
        result = await db.ipads.find_one_and_update(
            {"id": ipad_id, "is_in_pool": True},
            {
                "$set": {"is_in_pool": False, "user_id": payload.target_user_id, "updated_at": now_iso},
                "$push": {
                    "pool_history": {
                        "action": "assigned_by_admin",
                        "by": current_user["id"],
                        "target": payload.target_user_id,
                        "at": now_iso,
                    }
                },
            },
        )
        if result:
            success.append(result.get("itnr"))
        else:
            failed.append(ipad_id)

    return {
        "success_count": len(success),
        "failed_count": len(failed),
        "assigned_itnrs": success,
        "target_username": target_user.get("username"),
    }


@api_router.post("/ipads/bulk-claim")
@limiter.limit("30/minute")
async def bulk_claim_ipads(payload: BulkClaimRequest, request: Request, current_user: dict = Depends(get_current_user)):
    """Claim multiple iPads from the pool. Reports success and failure counts."""
    if not payload.ipad_ids:
        raise HTTPException(status_code=400, detail="Keine iPads ausgewählt")

    now_iso = datetime.now(UTC).isoformat()
    success = []
    failed = []

    for ipad_id in payload.ipad_ids:
        result = await db.ipads.find_one_and_update(
            {"id": ipad_id, "is_in_pool": True},
            {
                "$set": {"is_in_pool": False, "user_id": current_user["id"], "updated_at": now_iso},
                "$push": {"pool_history": {"action": "claimed", "by": current_user["id"], "at": now_iso}},
            },
        )
        if result:
            success.append(result.get("itnr"))
        else:
            failed.append(ipad_id)

    return {"success_count": len(success), "failed_count": len(failed), "claimed_itnrs": success}


@api_router.post("/ipads/{ipad_id}/release-to-pool")
@limiter.limit("60/minute")
async def release_ipad_to_pool(ipad_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Release an own iPad to the shared pool. Auto-dissolves active assignment."""
    # Validate ownership (admin can release any iPad)
    user_filter = await get_user_filter(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **user_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad nicht gefunden oder kein Zugriff")

    if ipad.get("is_in_pool"):
        raise HTTPException(status_code=400, detail="iPad ist bereits im Pool")

    # Auto-dissolve active assignment if exists
    dissolved_assignment = False
    if ipad.get("current_assignment_id"):
        assignment_id = ipad["current_assignment_id"]
        await db.assignments.update_one(
            {"id": assignment_id}, {"$set": {"is_active": False, "dissolved_at": datetime.now(UTC).isoformat()}}
        )
        # Mark contracts inactive
        await db.contracts.update_many(
            {"assignment_id": assignment_id},
            {"$set": {"is_active": False, "updated_at": datetime.now(UTC).isoformat()}},
        )
        dissolved_assignment = True

    now_iso = datetime.now(UTC).isoformat()
    await db.ipads.update_one(
        {"id": ipad_id},
        {
            "$set": {"is_in_pool": True, "current_assignment_id": None, "updated_at": now_iso},
            "$push": {"pool_history": {"action": "released", "by": current_user["id"], "at": now_iso}},
        },
    )

    return {
        "message": f"iPad {ipad['itnr']} in den Pool freigegeben",
        "itnr": ipad["itnr"],
        "dissolved_assignment": dissolved_assignment,
    }


@api_router.delete("/ipads/{ipad_id}")
async def delete_ipad(ipad_id: str, current_user: dict = Depends(get_current_user)):
    """
    Delete an iPad permanently from the database.
    Only allowed if iPad is not currently assigned.
    Admin can delete any iPad including pool iPads.
    """
    # Get iPad - admin sees all, user sees own + pool
    ipad_filter = await get_ipad_filter_with_pool(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})

    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found or access denied")

    # Non-admin users cannot delete pool iPads unless they are the importer
    if not is_admin(current_user) and ipad.get("is_in_pool") and ipad.get("user_id") != current_user["id"]:
        raise HTTPException(status_code=403, detail="Pool-iPads können nur vom Importeur oder Admin gelöscht werden")

    # Check if iPad is currently assigned
    if ipad.get("current_assignment_id"):
        raise HTTPException(status_code=400, detail="iPad ist aktuell zugewiesen. Bitte zuerst die Zuordnung auflösen.")

    # Update contracts: entferne ipad_id Referenz
    await db.contracts.update_many(
        {"ipad_id": ipad_id}, {"$set": {"ipad_id": None, "updated_at": datetime.now(UTC).isoformat()}}
    )

    # Delete orphaned contracts (no ipad_id, no student_id, no assignment_id)
    contracts_deleted = await db.contracts.delete_many(
        {
            "$and": [
                {"$or": [{"student_id": None}, {"student_id": {"$exists": False}}]},
                {"$or": [{"ipad_id": None}, {"ipad_id": {"$exists": False}}]},
                {"$or": [{"assignment_id": None}, {"assignment_id": {"$exists": False}}]},
            ]
        }
    )

    # Delete all assignments history for this iPad
    assignments_result = await db.assignments.delete_many({"ipad_id": ipad_id})

    # Delete the iPad
    await db.ipads.delete_one({"id": ipad_id})

    return {
        "message": f"iPad {ipad['itnr']} erfolgreich gelöscht",
        "deleted_assignments": assignments_result.deleted_count,
        "deleted_contracts": contracts_deleted.deleted_count,
    }


# Student management endpoints


class IPadStatusUpdate(BaseModel):
    status: str


@api_router.put("/ipads/{ipad_id}/status")
async def update_ipad_status(ipad_id: str, payload: IPadStatusUpdate, current_user: dict = Depends(get_current_user)):
    """
    Update iPad physical status (ok, defekt, gestohlen).
    Status indicates the physical condition, not assignment state.
    Assignment state is managed separately via current_assignment_id.
    """
    status_value = payload.status
    valid_statuses = ["ok", "defekt", "gestohlen"]
    if status_value not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    # Get the iPad first - admin sees all, user sees own + pool
    ipad_filter = await get_ipad_filter_with_pool(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")

    # Update iPad status (does not affect assignment)
    await db.ipads.update_one(
        {"id": ipad_id}, {"$set": {"status": status_value, "updated_at": datetime.now(UTC).isoformat()}}
    )

    return {"message": f"iPad status updated to {status_value}"}


class IPadUpdateRequest(BaseModel):
    itnr: Optional[str] = None
    snr: Optional[str] = None
    karton: Optional[str] = None
    pencil: Optional[str] = None
    typ: Optional[str] = None
    modell: Optional[str] = None
    ansch_jahr: Optional[str] = None
    ausleihe_datum: Optional[str] = None
    status: Optional[str] = None


@api_router.put("/ipads/{ipad_id}")
async def update_ipad(ipad_id: str, request: IPadUpdateRequest, current_user: dict = Depends(get_current_user)):
    """Update iPad information"""
    ipad_filter = await get_ipad_filter_with_pool(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")

    # Build update dict with only provided fields
    update_data = {}
    if request.itnr is not None:
        # Check if ITNr is unique (excluding current iPad)
        existing = await db.ipads.find_one({"itnr": request.itnr, "id": {"$ne": ipad_id}})
        if existing:
            raise HTTPException(status_code=400, detail="ITNr bereits vergeben")
        update_data["itnr"] = request.itnr
    if request.snr is not None:
        update_data["snr"] = request.snr
    if request.karton is not None:
        update_data["karton"] = request.karton
    if request.pencil is not None:
        update_data["pencil"] = request.pencil
    if request.typ is not None:
        update_data["typ"] = request.typ
    if request.modell is not None:
        # Empty string from frontend → null in DB
        update_data["modell"] = request.modell if request.modell else None
    if request.ansch_jahr is not None:
        update_data["ansch_jahr"] = request.ansch_jahr
    if request.ausleihe_datum is not None:
        update_data["ausleihe_datum"] = request.ausleihe_datum
    if request.status is not None:
        valid_statuses = ["ok", "defekt", "gestohlen"]
        if request.status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"Ungültiger Status. Erlaubt: {valid_statuses}")
        update_data["status"] = request.status

    if not update_data:
        raise HTTPException(status_code=400, detail="Keine Änderungen angegeben")

    update_data["updated_at"] = datetime.now(UTC).isoformat()

    await db.ipads.update_one({"id": ipad_id}, {"$set": update_data})

    # If ITNr changed, update related assignments and contracts
    if "itnr" in update_data:
        await db.assignments.update_many({"ipad_id": ipad_id}, {"$set": {"itnr": update_data["itnr"]}})
        await db.contracts.update_many({"ipad_id": ipad_id}, {"$set": {"itnr": update_data["itnr"]}})

    # Get updated iPad
    updated_ipad = await db.ipads.find_one({"id": ipad_id})
    return {
        "message": "iPad erfolgreich aktualisiert",
        "ipad": {
            "id": updated_ipad["id"],
            "itnr": updated_ipad["itnr"],
            "snr": updated_ipad.get("snr"),
            "karton": updated_ipad.get("karton"),
            "pencil": updated_ipad.get("pencil"),
            "typ": updated_ipad.get("typ"),
            "modell": updated_ipad.get("modell"),
            "ansch_jahr": updated_ipad.get("ansch_jahr"),
            "ausleihe_datum": updated_ipad.get("ausleihe_datum"),
            "status": updated_ipad.get("status", "ok"),
        },
    }


@api_router.post("/ipads/migrate-status")
async def migrate_ipad_status(current_user: dict = Depends(get_current_user)):
    """
    Migration endpoint to update old status values to new ones:
    - 'verfügbar' -> 'ok'
    - 'zugewiesen' -> 'ok'
    """
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can run migrations")

    try:
        # Update verfügbar and zugewiesen to ok
        result1 = await db.ipads.update_many(
            {"status": {"$in": ["verfügbar", "zugewiesen"]}}, {"$set": {"status": "ok"}}
        )

        return {"message": "iPad status migration completed", "updated_count": result1.modified_count}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Migration error: {str(e)}")


# iPad history and details
@api_router.get("/ipads/{ipad_id}/history")
async def get_ipad_history(ipad_id: str, current_user: dict = Depends(get_current_user)):
    # Get iPad - admin sees all, user sees own + pool
    ipad_filter = await get_ipad_filter_with_pool(current_user)
    ipad = await db.ipads.find_one({"id": ipad_id, **ipad_filter})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")

    # Get all assignments (active and inactive)
    assignments = await db.assignments.find({"ipad_id": ipad_id}).to_list(length=None)

    # Get all contracts for this iPad via ipad_id (new) or itnr (legacy)
    contracts = await db.contracts.find({"$or": [{"ipad_id": ipad_id}, {"itnr": ipad["itnr"]}]}).to_list(length=None)

    # Parse data safely
    try:
        ipad_data = iPad(**parse_from_mongo(ipad))
    except Exception as e:
        print(f"Error parsing iPad data: {e}")
        ipad_data = {
            "id": ipad.get("id"),
            "itnr": ipad.get("itnr"),
            "snr": ipad.get("snr", ""),
            "karton": ipad.get("karton", ""),
            "pencil": ipad.get("pencil", ""),
            "typ": ipad.get("typ", ""),
            "ansch_jahr": ipad.get("ansch_jahr", ""),
            "ausleihe_datum": ipad.get("ausleihe_datum", ""),
            "status": ipad.get("status", "ok"),
            "current_assignment_id": ipad.get("current_assignment_id"),
            "created_at": ipad.get("created_at"),
            "updated_at": ipad.get("updated_at"),
        }

    try:
        assignment_data = [Assignment(**parse_from_mongo(a)) for a in assignments]
    except Exception as e:
        print(f"Error parsing assignment data: {e}")
        assignment_data = []
        for a in assignments:
            try:
                assignment_data.append(Assignment(**parse_from_mongo(a)))
            except Exception as ae:
                print(f"Skipping assignment {a.get('id')}: {ae}")
                continue

    try:
        contract_data = []
        for c in contracts:
            try:
                # Handle contracts without file_data for display
                contract_dict = {
                    "id": c.get("id"),
                    "assignment_id": c.get("assignment_id"),
                    "ipad_id": c.get("ipad_id"),
                    "student_id": c.get("student_id"),
                    "itnr": c.get("itnr"),
                    "student_name": c.get("student_name"),
                    "filename": c.get("filename"),
                    "form_fields": c.get("form_fields", {}),
                    "uploaded_at": c.get("uploaded_at"),
                    "is_active": c.get("is_active", True),
                }
                contract_data.append(contract_dict)
            except Exception as ce:
                print(f"Skipping contract {c.get('id')}: {ce}")
                continue
    except Exception as e:
        print(f"Error parsing contract data: {e}")
        contract_data = []

    # Get owner info (current user_id of iPad)
    owner_username = None
    if ipad.get("user_id"):
        owner = await db.users.find_one({"id": ipad["user_id"]})
        if owner:
            owner_username = owner.get("username")

    # Enrich pool_history with username info
    raw_history = ipad.get("pool_history", []) or []
    user_id_set = set()
    for h in raw_history:
        if h.get("by"):
            user_id_set.add(h["by"])
        if h.get("target"):
            user_id_set.add(h["target"])
    user_map = {}
    if user_id_set:
        async for u in db.users.find({"id": {"$in": list(user_id_set)}}):
            user_map[u["id"]] = u.get("username", "?")
    pool_history = [
        {
            "action": h.get("action"),
            "by_user_id": h.get("by"),
            "by_username": user_map.get(h.get("by"), "Gelöschter User"),
            "target_username": user_map.get(h.get("target")) if h.get("target") else None,
            "at": h.get("at"),
        }
        for h in raw_history
    ]

    return {
        "ipad": ipad_data,
        "assignments": assignment_data,
        "contracts": contract_data,
        "owner_username": owner_username,
        "pool_history": pool_history,
    }


# Assignment dissolution
