"""Ersteinrichtung: das erste Admin-Konto - und die Tür, die danach zufällt.

/api/auth/setup ist der einzige Endpunkt, der ohne Anmeldung ein Konto anlegen kann. Er muss
es auch: in eine frische Installation käme sonst niemand hinein. Genau deshalb gelten hier
vier Regeln, und alle vier stehen in dieser Datei:

- Er legt nur an, solange die Benutzerliste LEER ist. Eine Anlage, die ihren letzten Admin
  verloren hat, bekommt kein Ersatzkonto mit einem Passwort, das in jeder Anleitung steht.
- Während einer Wiederherstellung legt er gar nichts an - dort ist die Benutzerliste kurz
  leer, ohne dass die Anlage neu wäre.
- Altbestand ist nur, wem das Feld ``role`` ganz fehlt. Wer eine Rolle hat, hat sie, weil
  jemand sie so gesetzt hat - auch die Rolle "user" und auch ein abgeschaltetes Konto.
- Das Standardpasswort steht in keiner Antwort. Wer den Aufruf macht, kennt es aus der
  Installationsanleitung; wer ihn nur erraten hat, soll es nicht daraus lernen.

Daneben steht GET /api/auth/setup-status: dieselbe Frage, nur lesend. Die Anmeldeseite stellt
sie bei jedem Laden, und sie hat dabei kein Token - also darf die Antwort nichts enthalten
außer dem Ja/Nein.

Am Ende der Datei steht der eindeutige Index auf users.username. Er ist keine fünfte Regel,
sondern das Netz unter allen vieren: Zwischen "gibt es schon Benutzer?" und dem Einfügen passt
ein zweiter Aufruf, und erst der Index verhindert, dass daraus zwei Konten desselben Namens
werden.
"""

import logging
from datetime import datetime, timedelta, timezone

import pytest
from pymongo.errors import DuplicateKeyError

from core.security import get_password_hash
from routes.auth import ensure_username_index
from routes.backup import RESTORE_RIEGEL_MAX_SEKUNDEN, SYSTEM_STATE


async def lehrkraft(db, name="lehrkraft"):
    """Ein gewöhnliches Benutzerkonto, wie es in jeder gewachsenen Anlage steht."""
    await db.users.insert_one({
        "id": f"u_{name}", "username": name, "password_hash": get_password_hash(f"pw_{name}_123"),
        "role": "user", "is_active": True,
    })


async def riegel_legen(db, alter_sekunden=0):
    """Den Riegel setzen, den eine laufende Wiederherstellung setzt - wahlweise als Leiche.

    Geschrieben wird genau dorthin, wo die Wiederherstellung ihn ablegt: in die Sammlung
    "system_state", die bewusst NICHT gesichert wird. Stünde er in einer gesicherten Sammlung,
    räumte die Wiederherstellung ihn mitten im eigenen Lauf weg.
    """
    seit = datetime.now(timezone.utc) - timedelta(seconds=alter_sekunden)
    await db[SYSTEM_STATE].insert_one({"type": "restore_running", "seit": seit.isoformat()})


# --- Der lesende Einrichtungsstand -------------------------------------------------------

async def test_setup_status_meldet_die_ausstehende_ersteinrichtung(db, client):
    """Leere Datenbank: ja, die Einrichtung steht aus - und die Frage legt nichts an.

    Früher fragte die Anmeldeseite mit POST /auth/setup, also mit einem schreibenden Aufruf.
    Deshalb steht hier auch, dass die Benutzerliste danach noch leer ist: Eine Frage, die
    nebenbei ein Konto anlegt, ist keine Frage.
    """
    antwort = await client.get("/api/auth/setup-status")

    assert antwort.status_code == 200, antwort.text
    assert antwort.json() == {"setup_required": True}
    assert await db.users.count_documents({}) == 0, "Eine reine Auskunft darf nichts anlegen"


async def test_setup_status_meldet_die_eingerichtete_anlage(welt, client):
    """Läuft die Anlage, steht nichts mehr aus - und mehr als das erfährt niemand."""
    antwort = await client.get("/api/auth/setup-status")

    assert antwort.status_code == 200, antwort.text
    assert antwort.json() == {"setup_required": False}


async def test_setup_status_verraet_den_verlorenen_admin_nicht(db, client):
    """Benutzer ja, Admin nein: nach außen ist auch das "eingerichtet".

    Zwei Gründe, und beide zählen. Sachlich: /auth/setup legt hier nichts mehr an, also steht
    auch nichts mehr aus - "true" hieße, der Anmeldeseite etwas zu versprechen, was der
    schreibende Endpunkt nicht einlöst. Und für einen Unangemeldeten wäre "dieser Anlage fehlt
    gerade der Admin" die nützlichste Auskunft überhaupt.

    Die Gleichheit prüft zugleich, dass keine Namen und keine Anzahlen mitkommen.
    """
    await lehrkraft(db)

    antwort = await client.get("/api/auth/setup-status")

    assert antwort.status_code == 200, antwort.text
    assert antwort.json() == {"setup_required": False}
    assert "lehrkraft" not in antwort.text, "Kein Name nach draußen"


# --- Die Ersteinrichtung selbst ----------------------------------------------------------

async def test_ersteinrichtung_nennt_das_passwort_nicht(db, client):
    """Der Erstlauf auf leerer Datenbank: Konto ja, Passwort in der Antwort nein."""
    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    assert "password" not in antwort.json()
    assert "admin123" not in antwort.text, "Das Standardpasswort darf nicht über die Leitung gehen"
    assert await db.users.count_documents({"role": "admin"}) == 1


async def test_in_eine_leere_datenbank_kommt_man_weiterhin_hinein(db, client):
    """Die Gegenprobe zu allen Riegeln: der Erstlauf muss funktionieren.

    Jeder Riegel in diesem Endpunkt schränkt ein, wann er noch anlegt. Zusammen könnten sie
    auch den Fall zuschlagen, für den es ihn gibt - und das fiele erst bei der nächsten
    Neuinstallation auf, wenn niemand mehr hineinkommt. Deshalb wird hier nicht nur gezählt,
    sondern mit dem Standardpasswort angemeldet: Nur das heißt wirklich "man kommt hinein".
    """
    antwort = await client.post("/api/auth/setup")
    assert antwort.status_code == 200, antwort.text

    anmeldung = await client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})

    assert anmeldung.status_code == 200, anmeldung.text
    assert anmeldung.json()["role"] == "admin"
    konto = await db.users.find_one({"username": "admin"})
    assert konto["is_active"] is True


async def test_vorhandener_admin_wird_nicht_angetastet(db, client):
    """Solange es einen Admin gibt, rührt der Aufruf nichts an - auch kein fremdes Konto.

    Neben dem Admin liegt hier ein Konto "admin" ohne Rollenfeld, ein Rest aus der Zeit vor
    den Rollen. Es ist der einzige Datensatz, den dieser Aufruf überhaupt anfassen könnte:
    Der Altbestands-Zweig steht VOR dem Riegel gegen das Standardkonto, also hält ihn allein
    die Abfrage nach einem vorhandenen Admin davon ab, diesem Konto ungefragt die Adminrolle
    zu geben.

    Ohne dieses Konto trug der Test nichts. Er lief gegen eine Anlage, in der alle Riegel
    zugleich greifen: Der Aufruf kehrt schon in der ersten Zeile um, und jeder einzeln
    ausgebaute Riegel wird vom nächsten aufgefangen - "nichts wurde angelegt" stimmte dann
    auch bei ausgebauten Riegeln noch.
    """
    admin_hash = get_password_hash("Admin-Passwort-123")
    alt_hash = get_password_hash("Altes-Passwort-123")
    await db.users.insert_many([
        {"id": "u_wieners", "username": "wieners", "password_hash": admin_hash,
         "role": "admin", "is_active": True},
        {"id": "u_alt", "username": "admin", "password_hash": alt_hash, "is_active": True},
    ])

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    assert "password" not in antwort.json()
    assert await db.users.count_documents({}) == 2, "Es darf nichts hinzugekommen sein"
    assert (await db.users.find_one({"id": "u_wieners"}))["password_hash"] == admin_hash
    alt = await db.users.find_one({"id": "u_alt"})
    assert "role" not in alt, "Wo es einen Admin gibt, verteilt dieser Aufruf keine Rollen"
    assert alt["password_hash"] == alt_hash, "Und erst recht keine Passwörter"


async def test_ohne_admin_aber_mit_benutzern_entsteht_kein_standardkonto(db, client):
    """Der Fall, der den Endpunkt gefährlich machte.

    Eine gewachsene Anlage verliert ihr letztes Admin-Konto - durch ein Versehen oder weil
    jemand es löscht. Legte der Endpunkt dann "admin/admin123" an, hätte sich jeder, der die
    Adresse kennt, Vollzugriff auf sämtliche Schülerdaten verschafft. Der Ausweg heißt
    Handarbeit in der Datenbank, nicht Bequemlichkeit.
    """
    await lehrkraft(db)

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    assert "password" not in antwort.json()
    assert await db.users.count_documents({"username": "admin"}) == 0, "Es darf kein Konto entstanden sein"
    assert await db.users.count_documents({}) == 1
    anmeldung = await client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert anmeldung.status_code == 401


# --- Der Riegel während einer Wiederherstellung -------------------------------------------

async def test_waehrend_einer_wiederherstellung_entsteht_kein_standardkonto(db, client):
    """Zwischen Leeren und Füllen ist die Benutzersammlung kurz leer - und genau auf diesen
    Zustand wartet dieser Endpunkt.

    Ohne den Riegel genügte ein Aufruf in diesem Augenblick, um sich admin/admin123 anlegen zu
    lassen: Die Hintertür wäre durch die Hintertür zurück. Die Benutzersammlung ist hier leer,
    damit wirklich nur der Riegel hält - alle anderen Abfragen des Endpunkts gingen in diesem
    Fall durch.
    """
    await riegel_legen(db)

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    assert "password" not in antwort.json()
    assert await db.users.count_documents({}) == 0, "Während einer Wiederherstellung wird nichts angelegt"
    anmeldung = await client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert anmeldung.status_code == 401


async def test_liegengebliebener_riegel_sperrt_die_ersteinrichtung_nicht_dauerhaft(db, client):
    """Die Gegenprobe, und sie wiegt schwer.

    Stirbt der Prozess mitten in der Wiederherstellung, bleibt der Riegel liegen; aufräumen
    kann ihn dann niemand mehr. Verfiele er nicht, käme auf einem frisch aufgesetzten Server
    nie wieder jemand hinein - und niemand wüsste, warum. Deshalb wird hier nicht nur gezählt,
    sondern mit dem Standardpasswort angemeldet.
    """
    await riegel_legen(db, alter_sekunden=RESTORE_RIEGEL_MAX_SEKUNDEN + 60)

    antwort = await client.post("/api/auth/setup")
    assert antwort.status_code == 200, antwort.text

    anmeldung = await client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})

    assert anmeldung.status_code == 200, anmeldung.text
    assert anmeldung.json()["role"] == "admin"


# --- Was "Altbestand" heißt und was nicht ------------------------------------------------

async def test_altbestands_admin_bekommt_die_rolle_ohne_passwort_in_der_antwort(db, client):
    """Ein "admin" aus der Zeit vor den Rollen bekommt seine Rolle nachgetragen.

    Sein Passwort bleibt, wie es ist - und steht erst recht nicht in der Antwort.
    """
    eigener_hash = get_password_hash("Eigenes-Passwort-123")
    await db.users.insert_one({
        "id": "u_alt", "username": "admin", "password_hash": eigener_hash, "is_active": True,
    })

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    assert "password" not in antwort.json()
    assert "admin123" not in antwort.text
    alt = await db.users.find_one({"username": "admin"})
    assert alt["role"] == "admin"
    assert alt["password_hash"] == eigener_hash, "Das eigene Passwort bleibt stehen"


async def test_entzogene_adminrolle_holt_der_setup_endpunkt_nicht_zurueck(db, client):
    """Ein Konto "admin", dem jemand die Adminrolle entzogen und das er abgeschaltet hat.

    Genau dieses Konto holte der Altbestands-Zweig zurück: Er suchte nach dem NAMEN "admin"
    und schrieb Rolle und ``is_active`` aus dem Standardkonto darüber. Ein unangemeldeter
    Aufruf genügte, um ein stillgelegtes Konto wieder scharf zu schalten - und der Zweig
    stand vor dem Riegel gegen das Standardkonto, fiel also auch dort nicht auf.
    """
    alt_hash = get_password_hash("Altes-Passwort-123")
    await db.users.insert_one({
        "id": "u_ex", "username": "admin", "password_hash": alt_hash,
        "role": "user", "is_active": False,
    })

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    konto = await db.users.find_one({"username": "admin"})
    assert konto["role"] == "user", "Eine entzogene Rolle kommt nicht von selbst zurück"
    assert konto["is_active"] is False, "Wer ein Konto abgeschaltet hat, hatte einen Grund"
    assert konto["password_hash"] == alt_hash
    assert await db.users.count_documents({}) == 1, "Und daneben entsteht auch nichts Neues"


async def test_abgeschalteter_altbestands_admin_bleibt_abgeschaltet(db, client):
    """Der echte Altbestand ohne Rollenfeld - aber abgeschaltet.

    Hier greift der Zweig zu Recht und trägt die fehlende Rolle nach. Mehr aber auch nicht:
    ``is_active`` steht ausdrücklich auf false, und das bleibt so. Sonst machte ein Aufruf
    ohne Anmeldung aus einem stillgelegten Konto wieder ein benutzbares.
    """
    await db.users.insert_one({
        "id": "u_alt", "username": "admin", "password_hash": get_password_hash("Altes-Passwort-123"),
        "is_active": False,
    })

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    alt = await db.users.find_one({"username": "admin"})
    assert alt["role"] == "admin", "Die fehlende Rolle gehört nachgetragen"
    assert alt["is_active"] is False, "Das abgeschaltete Konto bleibt abgeschaltet"
    anmeldung = await client.post("/api/auth/login",
                                  json={"username": "admin", "password": "Altes-Passwort-123"})
    assert anmeldung.status_code == 401, "Ein abgeschaltetes Konto meldet sich nicht an"


# --- Der eindeutige Index auf users.username ----------------------------------------------

async def konto(db, name, konto_id=None, passwort="Eigenes-Passwort-123"):
    await db.users.insert_one({
        "id": konto_id or f"u_{name}", "username": name,
        "password_hash": get_password_hash(passwort), "role": "admin", "is_active": True,
    })


def konkurrierender_aufruf(db, monkeypatch, konto_id="u_schneller", passwort="Eigenes-Passwort-123"):
    """Einen zweiten Einrichtungsaufruf genau in den Augenblick legen, auf den es ankommt.

    Zwischen "gibt es schon Benutzer?" und dem Einfügen liegt der Spalt, den der Index schließt.
    Das Vorbereiten des Dokuments ist der letzte Schritt davor - hier kommt der andere Aufruf
    dazwischen und legt den Admin an, den der laufende Aufruf gerade anlegen will.

    Er schreibt über eine eigene, synchrone Verbindung: nur so liegt er wirklich dazwischen.
    Ein zweiter Aufruf über denselben Client käme an dieser Stelle gar nicht zum Zug, und zwei
    echte Aufrufe nebeneinander träfen den Spalt nur manchmal - ein Test, der die Lage nur
    manchmal herstellt, hält sie nicht fest.
    """
    from pymongo import MongoClient

    import routes.auth as auth
    from tests.conftest import MONGO_URL

    echt = auth.prepare_for_mongo
    schon_dagewesen = []

    def dazwischen(dokument):
        if not schon_dagewesen:
            schon_dagewesen.append(True)
            sync = MongoClient(MONGO_URL)
            try:
                sync[db.name].users.insert_one({
                    "id": konto_id, "username": "admin",
                    "password_hash": get_password_hash(passwort),
                    "role": "admin", "is_active": True,
                })
            finally:
                sync.close()
        return echt(dokument)

    monkeypatch.setattr(auth, "prepare_for_mongo", dazwischen)


async def test_der_index_laesst_den_namen_kein_zweites_mal_zu(db):
    """Nachgesehen wird in der Datenbank, nicht im Rückgabewert.

    Die Anmeldung sucht das Konto allein über den Benutzernamen. Gäbe es ihn zweimal,
    entschiede die Reihenfolge in der Sammlung, wer sich anmeldet - und ob das stillgelegte
    oder das gültige Konto antwortet, wäre Zufall. "Index steht" heißt deshalb: die Datenbank
    nimmt den zweiten Namen nicht mehr an.
    """
    await konto(db, "admin")
    assert "username_eindeutig" not in await db.users.index_information()

    await ensure_username_index()

    index = (await db.users.index_information())["username_eindeutig"]
    assert index["key"] == [("username", 1)]
    assert index.get("unique") is True
    with pytest.raises(DuplicateKeyError):
        await konto(db, "admin", konto_id="u_zweiter")


@pytest.mark.parametrize(
    "namen,erwartet",
    [
        (["admin", "admin"], "1 Benutzername kommt mehrfach vor"),
        (["admin", "admin", "lehrkraft", "lehrkraft"], "2 Benutzernamen kommen mehrfach vor"),
    ],
    ids=["einer", "zwei"],
)
async def test_doppelte_namen_verhindern_den_index_und_die_meldung_nennt_die_zahl(
    db, caplog, namen, erwartet
):
    """Gegenprobe: Stehen die Namen schon doppelt im Bestand, lässt die Datenbank den Index
    nicht zu.

    Die Anwendung läuft trotzdem weiter - ein Deploy auf eine unsaubere Datenbank darf nicht
    die ganze Verwaltung stillstellen; ohne Anmeldung käme auch niemand mehr an die
    Benutzerverwaltung, um die Dubletten zu bereinigen. Die Meldung muss dann aber die ANZAHL
    nennen, und zwar in der richtigen Form: "1 Benutzernamen kommen mehrfach vor" liest sich
    wie ein Fehler im Programm und nicht wie ein Befund.
    """
    for nummer, name in enumerate(namen):
        await konto(db, name, konto_id=f"u_{nummer}")

    with caplog.at_level(logging.ERROR, logger="routes.auth"):
        await ensure_username_index()

    assert "username_eindeutig" not in await db.users.index_information(), \
        "Was die Datenbank ablehnt, darf hinterher nicht doch dastehen"
    assert erwartet in caplog.text, caplog.text


async def test_gleichzeitige_ersteinrichtung_legt_kein_zweites_konto_an(db, client, monkeypatch):
    """Zwei Ersteinrichtungen im selben Augenblick - der Index lässt nur eine durch.

    Für den zweiten Aufruf ist das kein Fehler: Gewollt war, dass es einen Admin gibt, und den
    gibt es jetzt. Er antwortet deshalb wie in jedem anderen Fall, in dem nichts mehr anzulegen
    war. Ein Serverfehler stünde hier besonders schlecht - er käme ausgerechnet bei der ersten
    Berührung mit einer frischen Installation.

    Angemeldet wird mit dem Passwort des ANDEREN Aufrufs: Nur das zeigt, dass sein Konto
    unberührt dasteht und nicht nachträglich überschrieben wurde.
    """
    await ensure_username_index()
    konkurrierender_aufruf(db, monkeypatch)

    antwort = await client.post("/api/auth/setup")

    assert antwort.status_code == 200, antwort.text
    assert "password" not in antwort.json()
    assert await db.users.count_documents({}) == 1, "Ein zweites Konto desselben Namens darf nicht entstehen"
    assert (await db.users.find_one({"username": "admin"}))["id"] == "u_schneller"
    anmeldung = await client.post("/api/auth/login",
                                  json={"username": "admin", "password": "Eigenes-Passwort-123"})
    assert anmeldung.status_code == 200, anmeldung.text
    assert anmeldung.json()["role"] == "admin"
