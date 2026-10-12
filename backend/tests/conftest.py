"""Gemeinsames Fundament für alle Tests.

ACHTUNG - diese Suite prüft das BACKEND. Vor einem Deploy gehört der Frontend-Build
dazu, denn er läuft durch ESLint und fängt Dinge, die hier niemand sieht:

    docker exec -w /app ipad_backend python -m pytest tests/ -q
    cd config && docker compose build frontend

Ein reiner Parser-Durchlauf über die JSX-Dateien genügt dafür nicht. Er sagt nur, dass
die Datei syntaktisch gültig ist - ein Verweis auf eine ESLint-Regel, die das Projekt
gar nicht kennt, bricht den Build trotzdem ab.


Jeder Test läuft gegen eine EIGENE, leere Datenbank, die danach verworfen wird. Das ist
gegenüber einer geteilten Testdatenbank etwas langsamer, aber Tests können sich dann nicht
gegenseitig beeinflussen - und ein Test, der nur in bestimmter Reihenfolge besteht, ist
schlimmer als gar keiner.

Die Anwendung wird mit ASGITransport direkt angesprochen, ohne laufenden Server: kein Port,
keine Wartezeiten, und die echten Routen samt Abhängigkeiten werden durchlaufen.
"""

import os
import sys
import uuid

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpx import ASGITransport, AsyncClient  # noqa: E402
from motor.motor_asyncio import AsyncIOMotorClient  # noqa: E402

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://mongodb:27017")


@pytest.fixture(autouse=True, scope="session")
def ohne_ratelimit():
    """Die Mengenbegrenzung für die gesamte Suite abschalten.

    /api/auth/login erlaubt fünf Versuche je Minute und Adresse. Alle Tests kommen von
    127.0.0.1, also bremst sie ab dem sechsten Test alles aus - die Fehler sähen dann nach
    Rechteproblemen aus, obwohl sie keine sind. Die Begrenzung selbst gehört in einen
    eigenen Test (siehe test_ratelimit.py), nicht als Rauschen in jeden anderen.
    """
    from core.config import limiter

    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest_asyncio.fixture
async def db():
    """Frische Datenbank je Test, danach restlos entfernt."""
    name = f"test_{uuid.uuid4().hex[:12]}"
    client = AsyncIOMotorClient(MONGO_URL)
    datenbank = client[name]

    # Alle Module, die db auf Modulebene importiert haben, auf die Testdatenbank umbiegen.
    import core.config
    import core.security

    originale = {}
    core.config.db = datenbank
    for modul in list(sys.modules.values()):
        if getattr(modul, "__name__", "").startswith(("routes.", "core.")) and hasattr(modul, "db"):
            originale[modul] = modul.db
            modul.db = datenbank

    yield datenbank

    for modul, original in originale.items():
        modul.db = original
    await client.drop_database(name)
    client.close()


@pytest_asyncio.fixture
async def client(db):
    """HTTP-Client gegen die echte Anwendung, ohne laufenden Server."""
    from main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def welt(db):
    """Eine kleine, aber vollständige Ausgangslage.

    Bildet die reale Lage ab, um die es im Umbau ging: eine Person, die zwei Bildungsgänge
    betreut, eine mit einem, eine ausgeschiedene, ein Admin ohne eigenen Bildungsgang.
    """
    from core.security import get_password_hash

    def benutzer(name, rolle="user"):
        return {
            "id": f"u_{name}",
            "username": name,
            "password_hash": get_password_hash(f"pw_{name}_123"),
            "role": rolle,
            "is_active": True,
        }

    await db.users.insert_many(
        [
            benutzer("admin", "admin"),
            benutzer("wieners", "admin"),
            benutzer("schaubach"),
            benutzer("bakenecker"),
            benutzer("ausgeschieden"),
        ]
    )
    await db.bildungsgaenge.insert_many(
        [
            {
                "id": f"bg_{n.lower()}",
                "name": n,
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
            for n in ["MEDA", "IT", "GYM", "Lehrkräfte"]
        ]
    )
    await db.zustaendigkeiten.insert_many(
        [
            {"id": "z1", "bildungsgang_id": "bg_meda", "user_id": "u_schaubach", "bis": None},
            {"id": "z2", "bildungsgang_id": "bg_it", "user_id": "u_schaubach", "bis": None},
            {"id": "z3", "bildungsgang_id": "bg_gym", "user_id": "u_bakenecker", "bis": None},
            {"id": "z4", "bildungsgang_id": "bg_lehrkräfte", "user_id": "u_wieners", "bis": None},
            # Beendet: Zugriff muss weg sein, Historie muss bleiben
            {"id": "z5", "bildungsgang_id": "bg_gym", "user_id": "u_ausgeschieden", "bis": "2026-08-01T00:00:00+00:00"},
        ]
    )
    return db


async def anmelden(client, username: str) -> dict:
    """Authorization-Header für diesen Benutzer. Passwort folgt dem Muster aus `welt`."""
    antwort = await client.post("/api/auth/login", json={"username": username, "password": f"pw_{username}_123"})
    assert antwort.status_code == 200, f"Anmeldung {username} fehlgeschlagen: {antwort.text}"
    return {"Authorization": f"Bearer {antwort.json()['access_token']}"}
