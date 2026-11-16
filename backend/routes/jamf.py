"""Jamf Pro aus der App heraus (/api/jamf/*, /api/ipads/{id}/jamf*).

Die eigentliche Anbindung steht in core/jamf.py. Hier liegt, wer was darf:

- Die Jamf-Adresse stellen nur Admins ein.
- Ihren Jamf-Login hinterlegt jede Person selbst; ohne Login sieht sie nichts von Jamf.
- Den Status gibt es nur für iPads, die die Person auch in der App sehen darf
  (get_ipad_filter) - Pool-Geräte also nur für Admins. Was Jamf darüber hinaus zeigt,
  entscheidet Jamf anhand ihres eigenen Kontos.
"""

from datetime import UTC, datetime

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from starlette.requests import Request

from core import jamf
from core.config import db, limiter
from core.router import api_router
from core.security import get_current_user, get_ipad_filter, require_admin_user


class JamfEinstellungen(BaseModel):
    url: str = ""


class JamfZugang(BaseModel):
    benutzername: str = Field(min_length=1, max_length=200)
    passwort: str = Field(min_length=1, max_length=500)


def _http(fehler: jamf.JamfFehler) -> HTTPException:
    return HTTPException(status_code=fehler.status, detail=fehler.meldung)


@api_router.get("/jamf/einstellungen")
async def jamf_einstellungen_lesen(current_user: dict = Depends(require_admin_user)):
    return {"url": await jamf.jamf_url() or ""}


@api_router.put("/jamf/einstellungen")
async def jamf_einstellungen_speichern(payload: JamfEinstellungen, current_user: dict = Depends(require_admin_user)):
    """Leere Adresse schaltet die Anbindung ab; die hinterlegten Logins bleiben stehen."""
    url = ""
    if payload.url.strip():
        try:
            url = jamf.normalisiere_url(payload.url)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    await db.global_settings.update_one(
        {"type": "jamf"}, {"$set": {"url": url, "updated_at": datetime.now(UTC).isoformat()}}, upsert=True
    )
    jamf._tokens.clear()
    return {"url": url}


@api_router.get("/jamf/zugang")
async def jamf_zugang_lesen(current_user: dict = Depends(get_current_user)):
    """Ob Jamf eingerichtet ist und ob diese Person einen Login hinterlegt hat - ohne Passwort."""
    url = await jamf.jamf_url()
    zugang = await db.jamf_zugaenge.find_one({"user_id": current_user["id"]})
    return {
        "eingerichtet": bool(url),
        "verknuepft": bool(zugang),
        "benutzername": (zugang or {}).get("benutzer"),
        "gesperrt": bool((zugang or {}).get("gesperrt")),
        "aktualisiert_am": (zugang or {}).get("aktualisiert_am"),
    }


@api_router.put("/jamf/zugang")
@limiter.limit("10/minute")  # Jamf sperrt Konten nach zu vielen Fehlversuchen
async def jamf_zugang_speichern(request: Request, payload: JamfZugang, current_user: dict = Depends(get_current_user)):
    try:
        await jamf.zugang_pruefen_und_speichern(current_user, payload.benutzername.strip(), payload.passwort)
    except jamf.JamfFehler as e:
        raise _http(e)
    return await jamf_zugang_lesen(current_user)


@api_router.delete("/jamf/zugang")
async def jamf_zugang_loeschen(current_user: dict = Depends(get_current_user)):
    await jamf.zugang_entfernen(current_user["id"])
    return {"message": "Jamf-Login entfernt."}


async def _ipad_fuer(user: dict, ipad_id: str) -> dict:
    ipad = await db.ipads.find_one({"id": ipad_id, **(await get_ipad_filter(user))})
    if not ipad:
        raise HTTPException(status_code=404, detail="iPad not found")
    return ipad


@api_router.get("/ipads/{ipad_id}/jamf")
async def jamf_status(ipad_id: str, current_user: dict = Depends(get_current_user)):
    ipad = await _ipad_fuer(current_user, ipad_id)
    try:
        geraet = await jamf.geraet_suchen(current_user, ipad.get("snr"))
    except jamf.JamfFehler as e:
        raise _http(e)
    return {"geraet": geraet}
