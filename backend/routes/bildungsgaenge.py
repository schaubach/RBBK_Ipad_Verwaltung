"""Bildungsgang routes (/api/bildungsgaenge/*).

Anlegen, Umbenennen und Löschen darf nur ein Admin. Die Liste darf jeder angemeldete
Benutzer lesen - sonst liessen sich Auswahlfelder nicht füllen und eine Bildungsgang-ID
nirgends zu einem Namen auflösen.

Zuständigkeiten werden nie gelöscht, sondern beendet (``bis`` gesetzt). Dadurch bleibt
nachvollziehbar, wer wann verantwortlich war, und der Zugriff endet trotzdem sofort -
siehe core.security.get_responsible_bildungsgang_ids.
"""

import re
from datetime import UTC, datetime
from typing import List

from core.config import db
from core.mongo import prepare_for_mongo
from core.router import api_router
from core.security import get_current_user, require_admin_user
from fastapi import Depends, HTTPException
from models.bildungsgang import (
    Bildungsgang,
    BildungsgangCreate,
    BildungsgangResponse,
    BildungsgangUpdate,
    Zustaendigkeit,
    ZustaendigkeitCreate,
    ZustaendigkeitPerson,
)

# Sammlungen, deren Datensätze einem Bildungsgang gehören. Beim Löschen wird hier gezählt.
OWNED_COLLECTIONS = ["ipads", "students", "assignments", "contracts"]


def _parse_dt(value):
    return datetime.fromisoformat(value) if isinstance(value, str) else value


def _iso(value):
    return value if isinstance(value, str) or value is None else value.isoformat()


async def _zustaendige(bildungsgang_id: str, nur_aktuelle: bool = False) -> List[ZustaendigkeitPerson]:
    """Zuständige eines Bildungsgangs, aktuelle zuerst."""
    query = {"bildungsgang_id": bildungsgang_id}
    if nur_aktuelle:
        query["bis"] = None
    eintraege = await db.zustaendigkeiten.find(query).sort("von", -1).to_list(length=None)
    user_ids = list({z["user_id"] for z in eintraege})
    namen = {
        u["id"]: u.get("username", "?")
        async for u in db.users.find({"id": {"$in": user_ids}}, {"id": 1, "username": 1})
    }
    personen = [
        ZustaendigkeitPerson(
            user_id=z["user_id"],
            username=namen.get(z["user_id"], "(gelöscht)"),
            von=_iso(z.get("von")),
            bis=_iso(z.get("bis")),
        )
        for z in eintraege
    ]
    # Aktuelle nach oben, danach nach Beginn absteigend
    return sorted(personen, key=lambda p: (p.bis is not None, p.von or ""), reverse=False)


async def _to_response(doc: dict) -> BildungsgangResponse:
    return BildungsgangResponse(
        id=doc["id"],
        name=doc["name"],
        description=doc.get("description"),
        zustaendige=await _zustaendige(doc["id"]),
        created_at=_parse_dt(doc["created_at"]),
        updated_at=_parse_dt(doc.get("updated_at", doc["created_at"])),
    )


@api_router.get("/bildungsgaenge", response_model=List[BildungsgangResponse])
async def list_bildungsgaenge(current_user: dict = Depends(get_current_user)):
    """Alle Bildungsgänge, alphabetisch, mit Zuständigen. Für jeden Angemeldeten lesbar."""
    docs = await db.bildungsgaenge.find({}).sort("name", 1).to_list(length=None)
    return [await _to_response(d) for d in docs]


@api_router.post("/bildungsgaenge", response_model=BildungsgangResponse)
async def create_bildungsgang(payload: BildungsgangCreate, current_user: dict = Depends(require_admin_user)):
    """Neuen Bildungsgang anlegen (nur Admin)."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Der Name darf nicht leer sein.")
    if await db.bildungsgaenge.find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}):
        raise HTTPException(status_code=400, detail=f'Ein Bildungsgang mit dem Namen "{name}" existiert bereits.')

    bg = Bildungsgang(name=name, description=(payload.description or "").strip() or None)
    await db.bildungsgaenge.insert_one(prepare_for_mongo(bg.dict()))
    return await _to_response(await db.bildungsgaenge.find_one({"id": bg.id}))


@api_router.put("/bildungsgaenge/{bildungsgang_id}", response_model=BildungsgangResponse)
async def update_bildungsgang(
    bildungsgang_id: str, payload: BildungsgangUpdate, current_user: dict = Depends(require_admin_user)
):
    """Umbenennen oder Beschreibung ändern (nur Admin). Die ID bleibt - Zuordnungen bleiben."""
    doc = await db.bildungsgaenge.find_one({"id": bildungsgang_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Bildungsgang nicht gefunden.")

    update = {"updated_at": datetime.now(UTC).isoformat()}
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Der Name darf nicht leer sein.")
        clash = await db.bildungsgaenge.find_one(
            {"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}, "id": {"$ne": bildungsgang_id}}
        )
        if clash:
            raise HTTPException(status_code=400, detail=f'Ein Bildungsgang mit dem Namen "{name}" existiert bereits.')
        update["name"] = name
    if payload.description is not None:
        update["description"] = payload.description.strip() or None

    await db.bildungsgaenge.update_one({"id": bildungsgang_id}, {"$set": update})
    return await _to_response(await db.bildungsgaenge.find_one({"id": bildungsgang_id}))


@api_router.delete("/bildungsgaenge/{bildungsgang_id}")
async def delete_bildungsgang(bildungsgang_id: str, current_user: dict = Depends(require_admin_user)):
    """Bildungsgang löschen (nur Admin).

    Verweigert, solange ihm Daten gehören. Ein Bildungsgang ist der Besitzer von Geräten,
    Schülern und Verträgen - ihn zu löschen, während daran noch etwas hängt, hiesse diese
    Daten unerreichbar zu machen oder mitzureissen. Beides darf kein Nebeneffekt sein.
    """
    doc = await db.bildungsgaenge.find_one({"id": bildungsgang_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Bildungsgang nicht gefunden.")

    bestand = {}
    for coll in OWNED_COLLECTIONS:
        n = await db[coll].count_documents({"bildungsgang_id": bildungsgang_id})
        if n:
            bestand[coll] = n
    if bestand:
        lesbar = {"ipads": "iPads", "students": "Schüler", "assignments": "Zuordnungen", "contracts": "Verträge"}
        teile = ", ".join(f"{n} {lesbar[k]}" for k, n in bestand.items())
        raise HTTPException(
            status_code=400,
            detail=f'Bildungsgang "{doc["name"]}" besitzt noch {teile}. '
            "Bitte diese zuerst einem anderen Bildungsgang zuordnen.",
        )

    await db.zustaendigkeiten.delete_many({"bildungsgang_id": bildungsgang_id})
    await db.bildungsgaenge.delete_one({"id": bildungsgang_id})
    return {"message": f'Bildungsgang "{doc["name"]}" wurde gelöscht.'}


@api_router.post("/bildungsgaenge/{bildungsgang_id}/zustaendige", response_model=BildungsgangResponse)
async def add_zustaendigkeit(
    bildungsgang_id: str, payload: ZustaendigkeitCreate, current_user: dict = Depends(require_admin_user)
):
    """Person als zuständig eintragen (nur Admin). Mehrere gleichzeitig sind erlaubt."""
    if not await db.bildungsgaenge.find_one({"id": bildungsgang_id}):
        raise HTTPException(status_code=404, detail="Bildungsgang nicht gefunden.")
    user = await db.users.find_one({"id": payload.user_id})
    if not user:
        raise HTTPException(status_code=404, detail="Benutzer nicht gefunden.")
    if not user.get("is_active", True):
        raise HTTPException(status_code=400, detail=f'Benutzer "{user["username"]}" ist deaktiviert.')

    laufend = await db.zustaendigkeiten.find_one(
        {"bildungsgang_id": bildungsgang_id, "user_id": payload.user_id, "bis": None}
    )
    if laufend:
        raise HTTPException(status_code=400, detail=f'"{user["username"]}" ist hier bereits zuständig.')

    z = Zustaendigkeit(bildungsgang_id=bildungsgang_id, user_id=payload.user_id, created_by=current_user["id"])
    await db.zustaendigkeiten.insert_one(prepare_for_mongo(z.dict()))
    return await _to_response(await db.bildungsgaenge.find_one({"id": bildungsgang_id}))


@api_router.delete("/bildungsgaenge/{bildungsgang_id}/zustaendige/{user_id}", response_model=BildungsgangResponse)
async def end_zustaendigkeit(
    bildungsgang_id: str, user_id: str, current_user: dict = Depends(require_admin_user)
):
    """Zuständigkeit beenden (nur Admin).

    Der Datensatz wird NICHT gelöscht, sondern mit ``bis`` abgeschlossen: der Zugriff endet
    sofort, die Historie bleibt. Die Daten des Bildungsgangs bleiben unberührt.
    """
    laufend = await db.zustaendigkeiten.find_one(
        {"bildungsgang_id": bildungsgang_id, "user_id": user_id, "bis": None}
    )
    if not laufend:
        raise HTTPException(status_code=404, detail="Keine laufende Zuständigkeit gefunden.")

    await db.zustaendigkeiten.update_one(
        {"id": laufend["id"]}, {"$set": {"bis": datetime.now(UTC).isoformat()}}
    )
    return await _to_response(await db.bildungsgaenge.find_one({"id": bildungsgang_id}))
