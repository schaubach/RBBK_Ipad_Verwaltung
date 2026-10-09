"""Benutzer löschen: das Konto geht, die Daten bleiben.

Der folgenschwerste Endpunkt der Anwendung. Vorher riss das Löschen eines Kontos alles mit,
was die Person je angelegt hatte - beim Ausscheiden einer Kollegin verschwand damit der halbe
Gerätebestand eines Bildungsgangs samt Schülerdaten und Vertrags-PDFs, die es nirgends sonst
gibt. Diese Tests prüfen deshalb weniger, DASS gelöscht wird, als vor allem, was NICHT
gelöscht wird.

Die Mengen sind absichtlich realistisch gewählt: ein Fehler, der einen halben Bestand kostet,
fällt bei 124 Geräten auf, bei dreien nicht.
"""

import pytest

from tests.conftest import anmelden

# Ein Vertrag ist ein PDF mit Anschrift des Schülers und Namen beider Erziehungsberechtigten.
# Diese Datei existiert nur hier - geht sie verloren, ist sie weg.
PDF = b"%PDF-1.4\n% Leihvertrag\n%%EOF"

LOESCHEN = "/api/admin/users/{}/complete"


def _ipad(kennung, bildungsgang_id, user_id, pool=False):
    return {
        "id": f"ip_{kennung}",
        "user_id": user_id,
        "bildungsgang_id": bildungsgang_id,
        "itnr": f"IT{kennung}",
        "snr": f"SN{kennung}",
        "status": "ok",
        "is_in_pool": pool,
        "pool_history": [],
    }


def _schueler(kennung, bildungsgang_id, user_id):
    return {
        "id": f"s_{kennung}",
        "user_id": user_id,
        "bildungsgang_id": bildungsgang_id,
        "sus_nachn": f"Nachname{kennung}",
        "sus_vorn": f"Vorname{kennung}",
        "sus_kl": "MEDA-U1",
        "sus_str_hnr": "Musterweg 3",
        "erz1_nachn": f"Nachname{kennung}",
        "erz1_vorn": "Erziehungsberechtigt",
    }


async def bestand_anlegen(db, user_id: str = "u_schaubach") -> dict:
    """Der Bestand, den eine einzelne Person über Jahre anlegt.

    Alles trägt ``user_id`` der Person (= angelegt von) und den ``bildungsgang_id`` der
    Einheit, der es gehört. Genau diese beiden Felder auseinanderzuhalten ist der Kern des
    ganzen Umbaus - und das, woran die Löschung sich halten muss.

    Gibt die Soll-Anzahlen zurück, damit die Tests gegen eine Zahl prüfen können statt gegen
    ein Gefühl.
    """
    ipads = [_ipad(f"meda{n}", "bg_meda", user_id) for n in range(80)]
    ipads += [_ipad(f"it{n}", "bg_it", user_id) for n in range(40)]
    # Poolgeräte gehören niemandem: kein Bildungsgang, aber von dieser Person angelegt.
    ipads += [_ipad(f"pool{n}", None, user_id, pool=True) for n in range(4)]
    await db.ipads.insert_many(ipads)

    schueler = [_schueler(f"meda{n}", "bg_meda", user_id) for n in range(30)]
    schueler += [_schueler(f"it{n}", "bg_it", user_id) for n in range(15)]
    await db.students.insert_many(schueler)

    await db.assignments.insert_many([
        {
            "id": f"z_meda{n}",
            "user_id": user_id,
            "bildungsgang_id": "bg_meda",
            "student_id": f"s_meda{n}",
            "ipad_id": f"ip_meda{n}",
            "itnr": f"ITmeda{n}",
            "student_name": f"Vornamemeda{n} Nachnamemeda{n}",
            "is_active": True,
            "assigned_at": "2026-02-01T08:00:00+00:00",
        }
        for n in range(25)
    ])

    await db.contracts.insert_many([
        {
            "id": f"v_meda{n}",
            "user_id": user_id,
            "bildungsgang_id": "bg_meda",
            "assignment_id": f"z_meda{n}",
            "ipad_id": f"ip_meda{n}",
            "student_id": f"s_meda{n}",
            "itnr": f"ITmeda{n}",
            "student_name": f"Vornamemeda{n} Nachnamemeda{n}",
            "filename": f"Leihvertrag_meda{n}.pdf",
            "file_data": PDF,
            "form_fields": {"NutzungEinhaltung": "/Yes", "erz1Ort": "Dortmund"},
            "uploaded_at": "2026-02-01T09:00:00+00:00",
            "is_active": True,
        }
        for n in range(18)
    ])

    return {"ipads": 124, "students": 45, "assignments": 25, "contracts": 18}


async def zaehlen(db) -> dict:
    return {
        "ipads": await db.ipads.count_documents({}),
        "students": await db.students.count_documents({}),
        "assignments": await db.assignments.count_documents({}),
        "contracts": await db.contracts.count_documents({}),
    }


async def nachfolgerin_eintragen(client, kopf, bildungsgang_id="bg_meda", user_id="u_bakenecker"):
    """Jemand übernimmt den verwaisten Bildungsgang - über den echten Endpunkt."""
    antwort = await client.post(
        f"/api/bildungsgaenge/{bildungsgang_id}/zustaendige", json={"user_id": user_id}, headers=kopf
    )
    assert antwort.status_code == 200, antwort.text


# ---------------------------------------------------------------------------
# Die Daten bleiben
# ---------------------------------------------------------------------------


async def test_loeschen_entfernt_nur_das_konto(welt, client):
    """124 Geräte, 45 Schüler, 25 Zuordnungen, 18 Verträge - nach dem Löschen alle noch da.

    Der eine Test, der diese Anwendung rechtfertigt.
    """
    soll = await bestand_anlegen(welt)
    kopf = await anmelden(client, "admin")

    antwort = await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)
    assert antwort.status_code == 200, antwort.text

    assert await zaehlen(welt) == soll
    assert await welt.users.find_one({"id": "u_schaubach"}) is None


async def test_poolgeraete_der_geloeschten_person_bleiben(welt, client):
    """Poolgeräte haben keinen Bildungsgang - sie dürfen trotzdem nicht mitgelöscht werden.

    Sie hängen an nichts, was sie schützt, ausser an der Regel selbst.
    """
    await bestand_anlegen(welt)
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    assert await welt.ipads.count_documents({"is_in_pool": True}) == 4


async def test_nachfolgerin_sieht_den_vollen_geraetebestand(welt, client):
    """Erhalten allein genügt nicht - die Daten müssen auch wieder erreichbar sein."""
    await bestand_anlegen(welt)
    kopf_admin = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)
    await nachfolgerin_eintragen(client, kopf_admin)

    kopf = await anmelden(client, "bakenecker")
    geraete = (await client.get("/api/ipads?bildungsgang_id=bg_meda", headers=kopf)).json()
    assert len(geraete) == 80


async def test_nachfolgerin_sieht_die_schueler(welt, client):
    await bestand_anlegen(welt)
    kopf_admin = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)
    await nachfolgerin_eintragen(client, kopf_admin)

    kopf = await anmelden(client, "bakenecker")
    schueler = (await client.get("/api/students?bildungsgang_id=bg_meda", headers=kopf)).json()
    assert len(schueler) == 30


async def test_nachfolgerin_sieht_die_zuordnungen(welt, client):
    await bestand_anlegen(welt)
    kopf_admin = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)
    await nachfolgerin_eintragen(client, kopf_admin)

    kopf = await anmelden(client, "bakenecker")
    zuordnungen = (await client.get("/api/assignments", headers=kopf)).json()
    assert len(zuordnungen) == 25


async def test_nachfolgerin_oeffnet_die_schuelerakte(welt, client):
    """Nicht nur die Liste, auch der einzelne Datensatz muss aufgehen.

    Die Liste filtert über den Bildungsgang, die Einzelansicht prüft die Zugehörigkeit je
    Datensatz - zwei verschiedene Wege, auf denen die Löschung einer Person den Zugriff
    unabhängig voneinander kaputtmachen könnte.
    """
    await bestand_anlegen(welt)
    kopf_admin = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)
    await nachfolgerin_eintragen(client, kopf_admin)

    kopf = await anmelden(client, "bakenecker")
    akte = await client.get("/api/students/s_meda0", headers=kopf)
    assert akte.status_code == 200, akte.text


async def test_angelegt_von_bleibt_am_datensatz_stehen(welt, client):
    """Die Löschung darf die Herkunftsangabe nicht ausradieren.

    ``user_id`` gewährt keinen Zugriff mehr, trägt aber "angelegt von" - die einzige Spur,
    aus der sich später rekonstruieren lässt, woher ein Datensatz stammt. Ein Blanken des
    Feldes wäre bequem und würde genau diese Spur vernichten.
    """
    await bestand_anlegen(welt)
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    geraet = await welt.ipads.find_one({"id": "ip_meda0"})
    assert geraet["user_id"] == "u_schaubach"
    assert geraet["bildungsgang_id"] == "bg_meda"


async def test_vertrag_bleibt_samt_pdf_herunterladbar(welt, client):
    """Die PDF-Datei selbst muss überleben, nicht nur der Datensatz darüber.

    Ein Vertrag ohne Datei ist für die Schule wertlos: es gibt kein zweites Exemplar.
    """
    await bestand_anlegen(welt)
    kopf_admin = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)
    await nachfolgerin_eintragen(client, kopf_admin)

    kopf = await anmelden(client, "bakenecker")
    assert len((await client.get("/api/contracts", headers=kopf)).json()) == 18

    datei = await client.get("/api/contracts/v_meda0/download", headers=kopf)
    assert datei.status_code == 200
    assert datei.content == PDF


async def test_geraetehistorie_ueberlebt_die_loeschung(welt, client):
    """Die Übergabe-Quittung muss die Person überdauern, der übergeben wurde.

    "Wem habe ich dieses Gerät gegeben" ist genau dann zu klären, wenn die Person weg ist.
    Deshalb liegt im Verlauf eine Namenskopie und keine blosse Benutzer-ID.
    """
    await bestand_anlegen(welt)
    await welt.ipads.update_one(
        {"id": "ip_meda0"},
        {"$set": {"pool_history": [{
            "action": "batch_assign",
            "by": "u_schaubach",
            "bildungsgang_id": "bg_meda",
            "uebergeben_an": {"user_id": "u_schaubach", "username": "schaubach"},
            "at": "2026-02-01T08:00:00+00:00",
        }]}},
    )
    kopf_admin = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)
    await nachfolgerin_eintragen(client, kopf_admin)

    kopf = await anmelden(client, "bakenecker")
    verlauf = await client.get("/api/ipads/ip_meda0/history", headers=kopf)
    assert verlauf.status_code == 200, verlauf.text
    eintrag = verlauf.json()["pool_history"][0]
    assert eintrag["uebergeben_an"] == "schaubach"


async def test_verwaiste_daten_bleiben_fuer_den_admin_erreichbar(welt, client):
    """Ohne Nachfolgerin ist der Bildungsgang unbetreut - verloren ist er trotzdem nicht.

    Das admin-Konto betreut selbst keinen Bildungsgang und hat deshalb die Alles-sehen-Sicht;
    von dort lässt sich der Bestand neu zuordnen.
    """
    await bestand_anlegen(welt)
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    geraete = (await client.get("/api/ipads?bildungsgang_id=bg_meda", headers=kopf)).json()
    assert len(geraete) == 80


async def test_geraet_ohne_bildungsgang_geht_nicht_verloren(welt, client):
    """Ein Altgerät ohne Zugehörigkeit hat nichts, was es schützt - ausser dieser Regel.

    Es ist weder Poolgerät noch einem Bildungsgang zugeordnet; nach der Löschung seines
    Erstellers hängt es an gar nichts mehr. Genau so ein Datensatz verschwindet als Erster,
    und genau er muss für den Admin sichtbar bleiben, damit er zugeordnet werden kann.
    """
    await welt.ipads.insert_one(_ipad("waise", None, "u_schaubach"))
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    ids = [i["id"] for i in (await client.get("/api/ipads", headers=kopf)).json()]
    assert "ip_waise" in ids


async def test_fremde_daten_bleiben_unberuehrt(welt, client):
    """Gelöscht wird eine Person, nicht ein Bildungsgang - GYM darf nichts davon merken."""
    await bestand_anlegen(welt)
    await welt.ipads.insert_one(_ipad("gym1", "bg_gym", "u_bakenecker"))
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    kopf_gym = await anmelden(client, "bakenecker")
    assert [i["id"] for i in (await client.get("/api/ipads", headers=kopf_gym)).json()] == ["ip_gym1"]


# ---------------------------------------------------------------------------
# Zuständigkeiten: beendet, nicht gelöscht
# ---------------------------------------------------------------------------


async def test_laufende_zustaendigkeiten_werden_beendet_nicht_geloescht(welt, client):
    """Beide Zuständigkeiten von schaubach (MEDA und IT) bekommen ein ``bis``, bleiben aber.

    Die Historie ist der einzige Beleg dafür, wer wann für wessen Daten verantwortlich war.
    """
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    eintraege = await welt.zustaendigkeiten.find({"user_id": "u_schaubach"}).to_list(length=None)
    assert len(eintraege) == 2
    assert all(z["bis"] is not None for z in eintraege)


async def test_antwort_nennt_die_zahl_der_beendeten_zustaendigkeiten(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)
    assert antwort.json()["zustaendigkeiten_beendet"] == 2


async def test_fremde_zustaendigkeit_bleibt_laufend(welt, client):
    """Nur die eigenen Zuständigkeiten enden - bakenecker behält GYM."""
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    assert await welt.zustaendigkeiten.find_one({"user_id": "u_bakenecker", "bis": None}) is not None


async def test_bereits_beendete_zustaendigkeit_behaelt_ihr_datum(welt, client):
    """Ein altes Enddatum darf nicht auf heute gesetzt werden.

    Sonst stünde in der Historie, die Person sei bis zum Tag ihrer Kontolöschung zuständig
    gewesen - sie war es aber nur bis August.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.delete(LOESCHEN.format("u_ausgeschieden"), headers=kopf)
    assert antwort.json()["zustaendigkeiten_beendet"] == 0

    alt = await welt.zustaendigkeiten.find_one({"id": "z5"})
    assert alt["bis"] == "2026-08-01T00:00:00+00:00"


async def test_historie_weist_die_geloeschte_person_als_geloescht_aus(welt, client):
    """Der Bildungsgang zeigt weiter, wer früher zuständig war - ohne Konto als "(gelöscht)"."""
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    meda = next(b for b in (await client.get("/api/bildungsgaenge", headers=kopf)).json() if b["id"] == "bg_meda")
    frueher = [p for p in meda["zustaendige"] if p["user_id"] == "u_schaubach"]
    assert len(frueher) == 1
    assert frueher[0]["username"] == "(gelöscht)"
    assert frueher[0]["bis"] is not None


# ---------------------------------------------------------------------------
# Die Antwort berichtet, was erhalten blieb
# ---------------------------------------------------------------------------


async def test_antwort_berichtet_die_erhaltenen_datensaetze(welt, client):
    """Die Meldung muss die Mengen nennen - sie ist für den Admin der einzige Beleg dafür,
    dass nichts verschwunden ist."""
    soll = await bestand_anlegen(welt)
    kopf = await anmelden(client, "admin")

    antwort = await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    assert antwort.json()["daten_erhalten"] == soll


async def test_antwort_berichtet_nullen_bei_leerem_bestand(welt, client):
    """Wer nie etwas angelegt hat, erzeugt Nullen - keine fehlenden Schlüssel."""
    kopf = await anmelden(client, "admin")

    daten = (await client.delete(LOESCHEN.format("u_bakenecker"), headers=kopf)).json()["daten_erhalten"]

    assert daten == {"ipads": 0, "students": 0, "assignments": 0, "contracts": 0}


async def test_antwort_zaehlt_nur_den_bestand_der_geloeschten_person(welt, client):
    """Die Meldung darf nicht den Gesamtbestand nennen, sonst sagt sie nichts aus."""
    await bestand_anlegen(welt)
    await welt.ipads.insert_one(_ipad("gym1", "bg_gym", "u_bakenecker"))
    kopf = await anmelden(client, "admin")

    antwort = await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    assert antwort.json()["daten_erhalten"]["ipads"] == 124
    assert await welt.ipads.count_documents({}) == 125


# ---------------------------------------------------------------------------
# Wer darf löschen, und was danach gilt
# ---------------------------------------------------------------------------


async def test_eigenes_konto_laesst_sich_nicht_loeschen(welt, client):
    """Sonst sperrt sich der letzte Admin selbst aus - und niemand kann mehr zuordnen."""
    kopf = await anmelden(client, "admin")

    antwort = await client.delete(LOESCHEN.format("u_admin"), headers=kopf)

    assert antwort.status_code == 400
    assert await welt.users.find_one({"id": "u_admin"}) is not None


async def test_lehrkraft_darf_niemanden_loeschen(welt, client):
    kopf = await anmelden(client, "bakenecker")

    antwort = await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    assert antwort.status_code == 403
    assert await welt.users.find_one({"id": "u_schaubach"}) is not None


async def test_ohne_anmeldung_kein_loeschen(welt, client):
    antwort = await client.delete(LOESCHEN.format("u_schaubach"))

    assert antwort.status_code == 401
    assert await welt.users.find_one({"id": "u_schaubach"}) is not None


async def test_unbekanntes_konto_meldet_404(welt, client):
    kopf = await anmelden(client, "admin")
    assert (await client.delete(LOESCHEN.format("u_gibtesnicht"), headers=kopf)).status_code == 404


async def test_zweites_loeschen_meldet_404(welt, client):
    """Ein doppelt abgeschickter Klick darf nicht noch einmal Zuständigkeiten anfassen."""
    kopf = await anmelden(client, "admin")

    assert (await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)).status_code == 200
    assert (await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)).status_code == 404


async def test_geloeschte_person_verliert_den_zugriff_sofort(welt, client):
    """Ein vor der Löschung ausgestelltes Token darf danach nichts mehr öffnen."""
    await bestand_anlegen(welt)
    kopf_opfer = await anmelden(client, "schaubach")
    assert (await client.get("/api/ipads", headers=kopf_opfer)).status_code == 200

    kopf_admin = await anmelden(client, "admin")
    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)

    assert (await client.get("/api/ipads", headers=kopf_opfer)).status_code == 401


async def test_geloeschte_person_kann_sich_nicht_mehr_anmelden(welt, client):
    kopf = await anmelden(client, "admin")
    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    antwort = await client.post(
        "/api/auth/login", json={"username": "schaubach", "password": "pw_schaubach_123"}
    )
    assert antwort.status_code == 401


async def test_neues_konto_gleichen_namens_erbt_nichts(welt, client):
    """Derselbe Name ist nicht dieselbe Person.

    Kommt die Kollegin zurück, bekommt sie ein neues Konto - und damit zunächst keinen
    Zugriff. Hinge der Zugriff am Benutzernamen statt an der Zuständigkeit, stünde ihr der
    alte Bestand sofort wieder offen, ohne dass jemand sie eingetragen hätte.
    """
    await bestand_anlegen(welt)
    kopf_admin = await anmelden(client, "admin")
    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf_admin)

    neu = await client.post(
        "/api/admin/users",
        json={"username": "schaubach", "password": "pw_schaubach_123", "role": "user"},
        headers=kopf_admin,
    )
    assert neu.status_code == 200, neu.text
    assert neu.json()["id"] != "u_schaubach"
    assert neu.json()["bildungsgaenge"] == []

    kopf = await anmelden(client, "schaubach")
    assert (await client.get("/api/ipads", headers=kopf)).json() == []
    assert await welt.ipads.count_documents({}) == 124


@pytest.mark.xfail(
    raises=KeyError,
    reason="BUG: _user_response liest user['created_at'] hart. Fehlt der Zeitstempel an EINEM "
    "Konto, bricht die ganze Benutzerliste ab - der Admin kommt an keinen Benutzer mehr heran, "
    "auch nicht an die 99 unbeschädigten. updated_at daneben wird bereits mit .get() gelesen.",
)
async def test_benutzerliste_vertraegt_konto_ohne_zeitstempel(welt, client):
    """Ein einzelnes unvollständiges Konto darf nicht die gesamte Benutzerverwaltung lahmlegen.

    Betrifft genau die Konten, die man dort loswerden will: Altbestände aus früheren Versionen
    und aus Sicherungen zurückgespielte Datensätze. Wer sie löschen möchte, muss sie sehen
    können - und sieht stattdessen einen Serverfehler.
    """
    kopf = await anmelden(client, "admin")

    antwort = await client.get("/api/admin/users", headers=kopf)

    assert antwort.status_code == 200


async def test_konto_verschwindet_aus_der_benutzerliste(welt, client):
    # Zeitstempel nachtragen, weil die Benutzerliste sonst abbricht (siehe xfail oben). Hier
    # geht es um die Löschung, nicht um die Robustheit der Liste.
    await welt.users.update_many({}, {"$set": {"created_at": "2026-01-01T00:00:00+00:00"}})
    kopf = await anmelden(client, "admin")

    await client.delete(LOESCHEN.format("u_schaubach"), headers=kopf)

    namen = [u["username"] for u in (await client.get("/api/admin/users", headers=kopf)).json()]
    assert "schaubach" not in namen
    assert sorted(namen) == ["admin", "ausgeschieden", "bakenecker", "wieners"]
