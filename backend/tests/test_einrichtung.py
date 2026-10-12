"""Ersteinrichtung: das erste Admin-Konto - und die Tür, die danach zufällt.

/api/auth/setup ist der einzige Endpunkt, der ohne Anmeldung ein Konto anlegen kann. Er muss
es auch: in eine frische Installation käme sonst niemand hinein. Genau deshalb gelten hier
drei Regeln, und alle drei stehen in dieser Datei:

- Er legt nur an, solange die Benutzerliste LEER ist. Eine Anlage, die ihren letzten Admin
  verloren hat, bekommt kein Ersatzkonto mit einem Passwort, das in jeder Anleitung steht.
- Altbestand ist nur, wem das Feld ``role`` ganz fehlt. Wer eine Rolle hat, hat sie, weil
  jemand sie so gesetzt hat - auch die Rolle "user" und auch ein abgeschaltetes Konto.
- Das Standardpasswort steht in keiner Antwort. Wer den Aufruf macht, kennt es aus der
  Installationsanleitung; wer ihn nur erraten hat, soll es nicht daraus lernen.

Daneben steht GET /api/auth/setup-status: dieselbe Frage, nur lesend. Die Anmeldeseite stellt
sie bei jedem Laden, und sie hat dabei kein Token - also darf die Antwort nichts enthalten
außer dem Ja/Nein.
"""

from core.security import get_password_hash


async def lehrkraft(db, name="lehrkraft"):
    """Ein gewöhnliches Benutzerkonto, wie es in jeder gewachsenen Anlage steht."""
    await db.users.insert_one({
        "id": f"u_{name}", "username": name, "password_hash": get_password_hash(f"pw_{name}_123"),
        "role": "user", "is_active": True,
    })


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
