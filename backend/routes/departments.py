"""Department routes (/api/departments/*).

Abteilungen verwaltet ausschliesslich ein Admin. Die Liste duerfen alle angemeldeten
Benutzer lesen, sonst liesse sich im Benutzerformular keine Abteilung auswaehlen und die
Anzeige koennte eine Abteilungs-ID nicht aufloesen.
"""

from datetime import UTC, datetime
from typing import List

from core.config import db
from core.mongo import prepare_for_mongo
from core.router import api_router
from core.security import get_current_user, require_admin_user
from fastapi import Depends, HTTPException
from models.department import (
    Department,
    DepartmentCreate,
    DepartmentResponse,
    DepartmentUpdate,
)


def _parse_dt(value):
    """Mongo liefert Zeitstempel je nach Schreibweg als Text oder als datetime."""
    return datetime.fromisoformat(value) if isinstance(value, str) else value


async def _to_response(doc: dict) -> DepartmentResponse:
    return DepartmentResponse(
        id=doc["id"],
        name=doc["name"],
        description=doc.get("description"),
        user_count=await db.users.count_documents({"department_id": doc["id"]}),
        created_at=_parse_dt(doc["created_at"]),
        updated_at=_parse_dt(doc.get("updated_at", doc["created_at"])),
    )


@api_router.get("/departments", response_model=List[DepartmentResponse])
async def list_departments(current_user: dict = Depends(get_current_user)):
    """Alle Abteilungen, alphabetisch. Fuer jeden angemeldeten Benutzer lesbar."""
    docs = await db.departments.find({}).sort("name", 1).to_list(length=None)
    return [await _to_response(d) for d in docs]


@api_router.post("/departments", response_model=DepartmentResponse)
async def create_department(payload: DepartmentCreate, current_user: dict = Depends(require_admin_user)):
    """Neue Abteilung anlegen (nur Admin)."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Der Name darf nicht leer sein.")

    # Gross-/Kleinschreibung ignorieren: "Technik" und "technik" waeren sonst zwei Abteilungen,
    # die in jeder Auswahlliste gleich aussehen.
    existing = await db.departments.find_one({"name": {"$regex": f"^{_escape(name)}$", "$options": "i"}})
    if existing:
        raise HTTPException(status_code=400, detail=f"Eine Abteilung mit dem Namen \"{name}\" existiert bereits.")

    department = Department(name=name, description=(payload.description or "").strip() or None)
    await db.departments.insert_one(prepare_for_mongo(department.dict()))
    return await _to_response(await db.departments.find_one({"id": department.id}))


@api_router.put("/departments/{department_id}", response_model=DepartmentResponse)
async def update_department(
    department_id: str, payload: DepartmentUpdate, current_user: dict = Depends(require_admin_user)
):
    """Abteilung umbenennen oder Beschreibung aendern (nur Admin).

    Die ID bleibt dabei unveraendert - zugeordnete Benutzer behalten ihre Abteilung.
    """
    doc = await db.departments.find_one({"id": department_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Abteilung nicht gefunden.")

    update = {"updated_at": datetime.now(UTC).isoformat()}
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Der Name darf nicht leer sein.")
        clash = await db.departments.find_one(
            {"name": {"$regex": f"^{_escape(name)}$", "$options": "i"}, "id": {"$ne": department_id}}
        )
        if clash:
            raise HTTPException(status_code=400, detail=f"Eine Abteilung mit dem Namen \"{name}\" existiert bereits.")
        update["name"] = name
    if payload.description is not None:
        update["description"] = payload.description.strip() or None

    await db.departments.update_one({"id": department_id}, {"$set": update})
    return await _to_response(await db.departments.find_one({"id": department_id}))


@api_router.delete("/departments/{department_id}")
async def delete_department(department_id: str, current_user: dict = Depends(require_admin_user)):
    """Abteilung loeschen (nur Admin).

    Verweigert, solange noch Benutzer zugeordnet sind. Die Alternative waere, deren Zuordnung
    stillschweigend zu entfernen - das waere ein unsichtbarer Nebeneffekt eines Loeschvorgangs,
    den niemand erwartet. Lieber eine klare Ansage, welche Benutzer noch daranhaengen.
    """
    doc = await db.departments.find_one({"id": department_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Abteilung nicht gefunden.")

    betroffen = await db.users.find({"department_id": department_id}, {"username": 1}).to_list(length=6)
    if betroffen:
        namen = ", ".join(u["username"] for u in betroffen[:5])
        rest = await db.users.count_documents({"department_id": department_id})
        mehr = f" und {rest - 5} weitere" if rest > 5 else ""
        raise HTTPException(
            status_code=400,
            detail=f"Abteilung \"{doc['name']}\" ist noch {rest} Benutzer(n) zugeordnet: {namen}{mehr}. "
            "Bitte diese zuerst einer anderen Abteilung zuordnen oder die Zuordnung entfernen.",
        )

    await db.departments.delete_one({"id": department_id})
    return {"message": f"Abteilung \"{doc['name']}\" wurde gelöscht."}


def _escape(text: str) -> str:
    """Regex-Sonderzeichen im Namen entschaerfen - sonst wuerde z.B. 'IT (neu)' die Suche brechen."""
    import re

    return re.escape(text)
