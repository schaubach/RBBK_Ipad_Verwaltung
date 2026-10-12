"""Der Lebenszeichen-Endpunkt /api/health - das Ziel des Container-Healthchecks.

Alle 30 Sekunden ruft Docker diesen Endpunkt auf, ohne Anmeldung und ohne dass jemand
hinsieht (config/docker-compose.yml). Daraus folgen die beiden Eigenschaften, die hier
geprüft werden:

- Er antwortet jedem, also darf in der Antwort nichts stehen, was einem Fremden beim
  Hineinkommen hilft - keine Version, keine Konfiguration, kein Name.
- Er fasst die Datenbank nicht an. Ein Aufruf alle 30 Sekunden ist genau die Stelle, an der
  ein beiläufiger Zugriff teuer wird - und davor stand an dieser Stelle der SCHREIBENDE
  Einrichtungs-Endpunkt, der nach dem Verlust des letzten Admin-Kontos binnen einer halben
  Minute ein Konto mit öffentlich bekanntem Passwort angelegt hätte.
"""


class DatenbankTabu:
    """Statthalter für ``db``, der jeden Zugriff sofort auffliegen lässt.

    Deutlicher als ein Aufruf-Zähler: Was den Endpunkt zur Datenbank greifen lässt, bringt
    den Test an genau der Zeile zum Fallen, statt eine Zahl am Ende nicht stimmen zu lassen.
    """

    def __getattr__(self, name):
        raise AssertionError(f"/api/health hat die Datenbank angefasst (db.{name})")

    def __getitem__(self, name):
        raise AssertionError(f"/api/health hat die Datenbank angefasst (db[{name!r}])")


async def test_health_antwortet_ohne_anmeldung_und_sagt_nur_den_zustand(client):
    """200 ohne Token, und in der Antwort steht genau ein Zustand - sonst nichts.

    Die Gleichheit ist Absicht: Eine Version oder ein Konfigurationswert, den jemand
    "zur Diagnose" hinzufügt, fällt hier auf, bevor er auf der Anmeldeseite jedem Fremden
    verrät, welcher Stand hier läuft.
    """
    antwort = await client.get("/api/health")

    assert antwort.status_code == 200, antwort.text
    assert antwort.json() == {"status": "ok"}


async def test_health_fasst_die_datenbank_nicht_an(client):
    """Der Healthcheck läuft alle 30 Sekunden - er darf die Datenbank nicht belasten.

    Und er darf erst recht nichts verändern: Dass der Healthcheck früher auf
    POST /api/auth/setup zeigte, ist der Grund, warum es diesen Endpunkt überhaupt gibt.
    """
    import routes.auth as auth

    echte_db = auth.db
    auth.db = DatenbankTabu()
    try:
        antwort = await client.get("/api/health")
    finally:
        auth.db = echte_db

    assert antwort.status_code == 200, antwort.text
    assert antwort.json() == {"status": "ok"}


async def test_health_bleibt_auch_in_einer_laufenden_anlage_wortkarg(welt, client):
    """Gegenprobe mit Bestand: Die Antwort hängt nicht davon ab, was in der Anlage steht.

    Sonst ließe sich aus dem Lebenszeichen herauslesen, ob und wie weit diese Installation
    in Betrieb ist.
    """
    antwort = await client.get("/api/health")

    assert antwort.json() == {"status": "ok"}
    for name in ["admin", "schaubach", "MEDA"]:
        assert name not in antwort.text
