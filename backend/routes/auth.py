"""Authentication routes (/api/auth/*)

Auto-extracted from monolithic server.py during refactor (Session 12).
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request

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
from models.user import (
    User,
    UserLogin,
)
from routes.backup import laeuft_wiederherstellung

logger = logging.getLogger(__name__)

# Eine einzige Antwort fuer jeden Fall, in dem nichts angelegt wird. Drei verschiedene Texte
# verrieten einem unangemeldeten Aufrufer, in welchem Zustand die Installation ist - ob es
# schon einen Admin gibt, ob ein Altbestandskonto herumliegt, ob Benutzer ohne Admin da sind.
SETUP_NICHT_NOETIG = "Setup not required"


async def _doppelte_benutzernamen() -> Optional[int]:
    """Wie viele Benutzernamen mehrfach vorkommen; None, wenn sich das nicht zaehlen laesst."""
    try:
        gruppen = await db.users.aggregate(
            [
                {"$group": {"_id": "$username", "anzahl": {"$sum": 1}}},
                {"$match": {"anzahl": {"$gt": 1}}},
                {"$count": "doppelte"},
            ]
        ).to_list(length=1)
    except Exception as e:
        logger.error("Doppelte Benutzernamen konnten nicht gezaehlt werden: %s", str(e))
        return None
    return gruppen[0]["doppelte"] if gruppen else 0


async def ensure_username_index() -> None:
    """Den eindeutigen Index auf users.username anlegen; aufgerufen beim Start (main.py).

    Die Anmeldung sucht das Konto allein ueber den Benutzernamen - doppelt vergeben darf er
    also nicht sein. Geprueft hat das bisher nur die Anwendung, und zwischen "gibt es den
    Namen schon?" und dem Einfuegen liegt ein Augenblick, in dem ein zweiter Aufruf dasselbe
    tun kann. Danach gibt es den Namen zweimal, und welches der beiden Konten sich anmeldet,
    entscheidet die Reihenfolge in der Sammlung. Der Index schliesst diese Luecke dort, wo sie
    entsteht, statt in jedem Anleger einzeln.

    Laesst er sich nicht anlegen - praktisch immer wegen doppelter Namen aus der Zeit davor -,
    laeuft die Anwendung trotzdem weiter. Ein Deploy auf eine unsaubere Datenbank darf nicht
    die ganze Verwaltung stillstellen; ohne Anmeldung kaeme auch niemand mehr an die
    Benutzerverwaltung, um die Dubletten zu bereinigen. Deshalb sagt die Meldung, WIE VIELE
    Namen zu bereinigen sind - "bitte bereinigen" ohne Zahl laesst den Leser ratlos zurueck.
    """
    try:
        await db.users.create_index("username", unique=True, name="username_eindeutig")
        return
    except Exception as e:
        # Dubletten sind der haeufige, aber nicht der einzige Grund (eine Datenbank laesst sich
        # auch nur lesend einbinden). Die Meldung nennt den Fall, der tatsaechlich vorliegt,
        # und schickt niemanden auf die Suche nach Dubletten, die es gar nicht gibt.
        doppelte = await _doppelte_benutzernamen()
        if doppelte:
            befund = (
                f"{doppelte} Benutzername kommt mehrfach vor"
                if doppelte == 1
                else f"{doppelte} Benutzernamen kommen mehrfach vor"
            )
        elif doppelte == 0:
            befund = "doppelte Benutzernamen gibt es dabei keine"
        else:
            befund = "ob Benutzernamen mehrfach vorkommen, liess sich nicht feststellen"
        logger.error(
            "ACHTUNG: Der eindeutige Index auf users.username konnte nicht angelegt werden - "
            "%s. Die Datenbank meldet: %s. Bis der Index steht, koennen zwei gleichzeitige "
            "Aufrufe denselben Benutzernamen doppelt anlegen; welches Konto sich danach "
            "anmeldet, entscheidet der Zufall.",
            befund,
            str(e),
        )


@api_router.get("/health")
async def health():
    """Lebenszeichen fuer den Container-Healthcheck (config/docker-compose.yml).

    Liegt hier, weil auth.py die Endpunkte sammelt, die ohne Token auskommen - und ohne Token
    muss dieser auskommen, denn der Healthcheck hat keines. Genau deshalb steht in der Antwort
    nichts ausser "ok": keine Version, keine Konfiguration, kein Datenbankzugriff. Er bestaetigt
    allein, dass die Anwendung Anfragen beantwortet, und veraendert dabei nichts - alle 30
    Sekunden ein schreibender Aufruf waere genau der Fehler, den dieser Endpunkt abloest.
    """
    return {"status": "ok"}


# Authentication endpoints
@api_router.get("/auth/setup-status")
async def setup_status():
    """Beantwortet nur, OB die Ersteinrichtung noch aussteht - sonst nichts.

    Die Login-Seite muss das bei jedem Laden wissen, hat dabei aber kein Token. Bisher fragte
    sie mit POST /auth/setup, also mit einem schreibenden Aufruf fuer eine reine Frage. Dieser
    Endpunkt liest nur; /auth/setup bleibt der Ersteinrichtung und install.sh vorbehalten.

    Zurueck kommt ein blosses Ja/Nein: kein Name, keine Anzahl, kein Passwort. Wer ohne
    Anmeldung fragt, soll daraus nichts ueber die Anlage lernen, was ihm beim Hineinkommen
    hilft. "true" heisst genau das, was /auth/setup auch wirklich noch anlegen wuerde: eine
    voellig leere Benutzerliste. Eine Anlage, die bloss ihr letztes Admin-Konto verloren hat,
    meldet hier "false" - sie bekommt kein Standardkonto mehr, und dass ihr der Admin fehlt,
    geht einen Fremden erst recht nichts an.
    """
    # Projektion auf _id: Es zaehlt allein, OB ueberhaupt ein Benutzer existiert. Die Felder
    # duerfen diesen Endpunkt gar nicht erst erreichen, damit sie auch nie in eine Antwort
    # rutschen koennen.
    irgendein_benutzer = await db.users.find_one({}, {"_id": 1})
    return {"setup_required": irgendein_benutzer is None}


@api_router.post("/auth/setup", response_model=dict)
async def setup_admin():
    """Ersteinrichtung: legt das erste Admin-Konto an, solange noch kein Benutzer existiert.

    Der Endpunkt braucht keine Anmeldung, sonst kaeme niemand in eine frische Installation
    hinein. Deshalb legt er nur an, wenn die Benutzerliste vollstaendig leer ist: Verliert die
    Schule spaeter ihr letztes Admin-Konto, stuende die Verwaltung sonst mit einem Passwort
    offen, das in jeder Anleitung steht. In dem Fall muss ein Admin von Hand in der Datenbank
    nachgetragen werden - das ist der Preis dafuer, dass hier keine Hintertuer bleibt.

    Das Standardpasswort steht nicht in der Antwort; wer die Ersteinrichtung ausfuehrt, kennt es
    aus der Installationsanleitung.
    """
    # Check if ANY admin user exists (not just username "admin")
    existing_admin = await db.users.find_one({"role": "admin"})
    if existing_admin:
        return {"message": SETUP_NICHT_NOETIG}

    # Nur ein ECHTER Altbestand: ein Benutzer "admin", dem das Feld role ganz fehlt. Die
    # fruehere Abfrage traf jeden Benutzer dieses Namens - auch einen, dem jemand die
    # Adminrolle bewusst entzogen oder den er abgeschaltet hatte. Ein unangemeldeter Aufruf
    # holte ihn damit zurueck, und das mitgeschriebene is_active machte ihn gleich wieder
    # nutzbar. Dieser Zweig stand ausserdem VOR dem Riegel weiter unten und umging ihn.
    legacy_admin = await db.users.find_one({"username": "admin", "role": {"$exists": False}})
    if legacy_admin:
        # Nur die fehlende Rolle nachtragen. Ein abgeschaltetes Konto bleibt abgeschaltet -
        # wer es abgeschaltet hat, hatte einen Grund.
        nachtrag = {"role": "admin"}
        if "is_active" not in legacy_admin:
            nachtrag["is_active"] = True
        # Ueber _id, nicht ueber id: dieser Zweig ist fuer unvollstaendige Altdatensaetze da
        # und darf gerade nicht voraussetzen, dass das Feld id schon existiert.
        await db.users.update_one({"_id": legacy_admin["_id"]}, {"$set": nachtrag})
        logger.warning(
            "Setup-Endpunkt hat den Altbestands-Benutzer 'admin' zur Rolle admin erhoben - "
            "dieser Aufruf kam ohne Anmeldung."
        )
        return {"message": SETUP_NICHT_NOETIG}

    # Waehrend einer Wiederherstellung ist die Benutzersammlung zwischen Leeren und Fuellen
    # kurz leer. Ohne diese Abfrage reichte ein Aufruf in genau diesem Augenblick, um sich
    # admin/admin123 anlegen zu lassen - die Hintertuer waere durch die Hintertuer zurueck.
    if await laeuft_wiederherstellung():
        logger.warning("Setup-Endpunkt waehrend einer laufenden Wiederherstellung aufgerufen - abgelehnt.")
        return {"message": SETUP_NICHT_NOETIG}

    # Es gibt kein Admin-Konto mehr, aber noch Benutzer: Das ist keine Ersteinrichtung, sondern
    # eine Installation, die ihren Admin verloren hat. Ein Standardkonto waere hier ein offenes
    # Tor fuer jeden, der den Endpunkt kennt.
    anzahl_benutzer = await db.users.count_documents({})
    if anzahl_benutzer:
        logger.warning(
            "Setup-Endpunkt aufgerufen, ohne dass ein Admin-Konto existiert - es gibt aber noch "
            "%d Benutzer. Es wurde NICHTS angelegt. Ein Admin-Konto muss von Hand in der "
            "Datenbank eingetragen werden.",
            anzahl_benutzer,
        )
        return {"message": SETUP_NICHT_NOETIG}

    # Leere Datenbank - das ist der echte Erstlauf.
    hashed_password = get_password_hash("admin123")
    user = User(username="admin", password_hash=hashed_password, role="admin", is_active=True)
    user_dict = prepare_for_mongo(user.dict())
    try:
        await db.users.insert_one(user_dict)
    except DuplicateKeyError:
        # Zwei Aufrufe gleichzeitig: der andere war zwischen der Pruefung oben und diesem
        # Einfuegen schneller. Der Index hat das zweite Konto verhindert - genau dafuer ist er
        # da. Gewollt war, dass es einen Admin gibt, und den gibt es jetzt; also ist das kein
        # Fehler, sondern derselbe Fall wie oben: es war nichts mehr anzulegen.
        logger.warning(
            "Ersteinrichtung doppelt aufgerufen: Der Benutzer 'admin' war im selben Augenblick "
            "schon von einem anderen Aufruf angelegt worden. Es wurde nichts veraendert."
        )
        return {"message": SETUP_NICHT_NOETIG}
    logger.warning(
        "Ersteinrichtung: Benutzer 'admin' mit dem Standardpasswort angelegt. Das Passwort ist "
        "oeffentlich bekannt und muss nach der ersten Anmeldung sofort geaendert werden."
    )
    return {"message": "Admin user created successfully", "username": "admin"}


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
