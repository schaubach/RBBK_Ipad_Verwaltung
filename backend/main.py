"""Application entry point.

Assembles the FastAPI app from the modular routes/core/models package: importing ``routes``
registers every endpoint on the shared ``core.router.api_router`` (see routes/__init__.py),
which is then mounted here together with the same middleware/limiter/scheduler setup that used
to live inline in the old monolithic server.py.
"""

import asyncio
import logging
import os

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware

from core.config import client, limiter
from core.middleware import SecurityHeadersMiddleware
from core.router import api_router
import routes  # noqa: F401  (import side-effect: registers all endpoints on api_router)
from routes.auth import ensure_username_index
from routes.backup import backup_scheduler_loop, ensure_itnr_index

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="iPad Management System")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(api_router)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get(
        "CORS_ORIGINS", "http://localhost:3000,https://vertraege-lab.preview.emergentagent.com"
    ).split(","),
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
async def start_backup_scheduler():
    asyncio.create_task(backup_scheduler_loop())


@app.on_event("startup")
async def create_indexes():
    """Die ITNr bezeichnet ein Stueck Hardware und ist schulweit eindeutig - das schreibt der
    Index in die Datenbank, statt es nur in der Anwendung zu pruefen.

    Der Batch-Upload verlaesst sich darauf: sein atomares ``$setOnInsert`` schliesst das
    Wettrennen zweier gleichzeitiger Laeufe um dieselbe neue ITNr nur, wenn die zweite
    Einfuegung an diesem Index scheitert. Ohne ihn legen beide das Geraet an.

    Laesst der Index sich nicht anlegen - praktisch immer wegen Dubletten aus der Zeit davor -,
    laeuft die Anwendung trotzdem weiter. Ein Deploy auf eine unsaubere Datenbank darf nicht
    die ganze Verwaltung stillstellen; die Meldung im Log sagt, wie viele Nummern zu bereinigen
    sind, und bis dahin bleibt es beim alten Zustand.

    Dasselbe Anlegen laeuft nach jeder Wiederherstellung - der Index steht in der Datenbank und
    nicht in der Backup-Datei. Deshalb liegt es in routes/backup.py, wo der zweite Aufrufer
    sitzt, und nicht hier (ein Import in die andere Richtung waere ein Ringschluss).
    """
    await ensure_itnr_index()


@app.on_event("startup")
async def create_username_index():
    """Der Benutzername ist der Schluessel der Anmeldung: das Konto wird allein ueber ihn
    gesucht. Gibt es ihn zweimal, entscheidet der Zufall, wer sich anmeldet. Der Index sichert
    die Eindeutigkeit in der Datenbank zu - die Ersteinrichtung und die Benutzerverwaltung
    pruefen sie vorher, aber zwischen Pruefung und Einfuegen passt ein zweiter Aufruf.

    Wie beim Index auf ipads.itnr gilt: laesst er sich nicht anlegen - praktisch immer wegen
    doppelter Namen aus der Zeit davor -, laeuft die Anwendung trotzdem weiter. Sonst stuende
    nach einem Deploy auf eine unsaubere Datenbank die ganze Verwaltung still, und niemand
    kaeme mehr hinein, um die Dubletten zu bereinigen. Die Meldung im Log sagt, wie viele
    Namen betroffen sind.

    Anders als bei ipads.itnr braucht ihn keine Wiederherstellung neu: die ersetzt die
    Benutzer mit delete_many/insert_many und laesst die Indexe stehen. Deshalb steht der
    Aufruf nur hier, und die Funktion selbst in routes/auth.py - dort sitzt die
    Ersteinrichtung, die ohne ihn ein zweites Admin-Konto anlegen koennte.
    """
    await ensure_username_index()


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
