"""Bildungsgänge und Zuständigkeiten: /api/bildungsgaenge/*.

Der Bildungsgang ist der Besitzer aller Daten, die Zuständigkeit ist der einzige Weg zu
ihnen. Wer hier anlegen, umbenennen, löschen oder Zuständigkeiten setzen darf, entscheidet
damit über jeden Zugriff in der restlichen Anwendung - deshalb liegt der Schwerpunkt auf
den Wegen, die scheitern MÜSSEN, und auf dem, was nach einer Änderung erhalten bleibt.
"""

from datetime import datetime

import pytest

from tests.conftest import anmelden

PFAD = "/api/bildungsgaenge"


async def liste(client, kopf) -> list:
    antwort = await client.get(PFAD, headers=kopf)
    assert antwort.status_code == 200, antwort.text
    return antwort.json()


async def hole(client, kopf, bildungsgang_id: str) -> dict:
    """Ein Bildungsgang aus der Liste - die Liste ist der einzige Leseweg."""
    treffer = [b for b in await liste(client, kopf) if b["id"] == bildungsgang_id]
    assert treffer, f"{bildungsgang_id} ist nicht in der Liste"
    return treffer[0]


def aktuelle(bildungsgang: dict) -> set:
    """Namen der derzeit Zuständigen (bis is None)."""
    return {z["username"] for z in bildungsgang["zustaendige"] if z["bis"] is None}


def beendete(bildungsgang: dict) -> set:
    return {z["username"] for z in bildungsgang["zustaendige"] if z["bis"] is not None}


async def geraet(db, ipad_id, bildungsgang_id):
    await db.ipads.insert_one({
        "id": ipad_id, "bildungsgang_id": bildungsgang_id, "is_in_pool": False,
        "itnr": f"IT{ipad_id}", "snr": f"SN{ipad_id}", "status": "ok", "user_id": "u_admin",
    })


async def sichtbare_ipads(client, kopf) -> list:
    antwort = await client.get("/api/ipads", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    return sorted(i["id"] for i in antwort.json())


# --------------------------------------------------------------------------- Rechte


async def test_liste_ist_fuer_jeden_angemeldeten_lesbar(welt, client):
    """Auch Bildungsgänge, für die man nicht zuständig ist.

    Die Liste ist keine Datenfreigabe, sondern ein Namensverzeichnis: ohne sie liesse sich
    in keinem Auswahlfeld eine ID zu einem Namen auflösen.
    """
    for wer in ["schaubach", "bakenecker", "ausgeschieden", "admin"]:
        kopf = await anmelden(client, wer)
        namen = [b["name"] for b in await liste(client, kopf)]
        assert namen == ["GYM", "IT", "Lehrkräfte", "MEDA"], f"{wer} sieht {namen}"


async def test_liste_ohne_anmeldung_gesperrt(client):
    assert (await client.get(PFAD)).status_code == 401


async def test_nur_admin_darf_anlegen(welt, client):
    lehrkraft = await anmelden(client, "schaubach")
    abgelehnt = await client.post(PFAD, json={"name": "Pflege"}, headers=lehrkraft)
    assert abgelehnt.status_code == 403
    assert await welt.bildungsgaenge.count_documents({}) == 4

    admin = await anmelden(client, "admin")
    assert (await client.post(PFAD, json={"name": "Pflege"}, headers=admin)).status_code == 200


async def test_nur_admin_darf_umbenennen(welt, client):
    """Auch der eigene Bildungsgang nicht: Zuständigkeit ist kein Besitz."""
    lehrkraft = await anmelden(client, "schaubach")
    antwort = await client.put(f"{PFAD}/bg_meda", json={"name": "Mediengestaltung"}, headers=lehrkraft)
    assert antwort.status_code == 403
    assert (await welt.bildungsgaenge.find_one({"id": "bg_meda"}))["name"] == "MEDA"


async def test_nur_admin_darf_loeschen(welt, client):
    lehrkraft = await anmelden(client, "schaubach")
    antwort = await client.delete(f"{PFAD}/bg_meda", headers=lehrkraft)
    assert antwort.status_code == 403
    assert await welt.bildungsgaenge.find_one({"id": "bg_meda"}) is not None


async def test_nur_admin_darf_zustaendige_eintragen(welt, client):
    lehrkraft = await anmelden(client, "schaubach")
    antwort = await client.post(
        f"{PFAD}/bg_meda/zustaendige", json={"user_id": "u_bakenecker"}, headers=lehrkraft
    )
    assert antwort.status_code == 403
    assert await welt.zustaendigkeiten.count_documents({"user_id": "u_bakenecker"}) == 1


async def test_nur_admin_darf_zustaendigkeit_beenden(welt, client):
    """Eine Lehrkraft kann sich nicht selbst eintragen und auch nicht selbst austragen."""
    lehrkraft = await anmelden(client, "schaubach")
    antwort = await client.delete(f"{PFAD}/bg_meda/zustaendige/u_schaubach", headers=lehrkraft)
    assert antwort.status_code == 403
    assert (await welt.zustaendigkeiten.find_one({"id": "z1"}))["bis"] is None


# --------------------------------------------------------------------------- Anlegen


async def test_anlegen_liefert_den_neuen_bildungsgang_ohne_zustaendige(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.post(PFAD, json={"name": "Pflege", "description": "Fachschule"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    neu = antwort.json()
    assert neu["name"] == "Pflege"
    assert neu["description"] == "Fachschule"
    assert neu["zustaendige"] == []
    assert neu["id"] not in ["bg_meda", "bg_it", "bg_gym", "bg_lehrkräfte"]
    assert neu["id"] in [b["id"] for b in await liste(client, admin)]


async def test_doppelter_name_wird_unabhaengig_von_der_schreibweise_abgelehnt(welt, client):
    admin = await anmelden(client, "admin")
    for variante in ["MEDA", "meda", "MeDa", "  meda  "]:
        antwort = await client.post(PFAD, json={"name": variante}, headers=admin)
        assert antwort.status_code == 400, f'"{variante}" wurde angenommen'
        assert "existiert bereits" in antwort.json()["detail"], variante
    assert await welt.bildungsgaenge.count_documents({}) == 4


async def test_doppelter_name_mit_umlaut_wird_abgelehnt(welt, client):
    """„LEHRKRÄFTE" ist derselbe Bildungsgang wie „Lehrkräfte".

    Zwei Einträge mit demselben Namen bedeuten zwei getrennte Bestände, zwischen denen
    niemand mehr unterscheiden kann - bei deutschen Namen ist das kein Randfall.
    """
    admin = await anmelden(client, "admin")
    antwort = await client.post(PFAD, json={"name": "LEHRKRÄFTE"}, headers=admin)
    assert antwort.status_code == 400, "Groß-/Kleinschreibung darf keinen zweiten Bestand anlegen"
    assert "existiert bereits" in antwort.json()["detail"]
    assert await welt.bildungsgaenge.count_documents({}) == 4


async def test_leerer_name_wird_abgelehnt(welt, client):
    admin = await anmelden(client, "admin")
    for leer in ["", "   ", "\t"]:
        antwort = await client.post(PFAD, json={"name": leer}, headers=admin)
        assert antwort.status_code == 400, f"{leer!r} wurde angenommen"
        assert "leer" in antwort.json()["detail"], leer
    assert await welt.bildungsgaenge.count_documents({}) == 4


async def test_name_wird_ohne_umschliessende_leerzeichen_gespeichert(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.post(PFAD, json={"name": "  Pflege  "}, headers=admin)
    assert antwort.status_code == 200
    assert antwort.json()["name"] == "Pflege"


async def test_name_mit_regex_sonderzeichen_wird_woertlich_verglichen(welt, client):
    """„IT (neu)" ist ein Name, kein Suchmuster.

    Ungeschützt wäre „IT (neu)" das Muster ^IT (neu)$ - und würde auf den bereits
    vorhandenen „IT neu" passen. Der Admin bekäme dann die Meldung, ein Name existiere
    bereits, den es gar nicht gibt.
    """
    admin = await anmelden(client, "admin")
    assert (await client.post(PFAD, json={"name": "IT neu"}, headers=admin)).status_code == 200
    assert (await client.post(PFAD, json={"name": "BFS 1"}, headers=admin)).status_code == 200

    mit_klammern = await client.post(PFAD, json={"name": "IT (neu)"}, headers=admin)
    assert mit_klammern.status_code == 200, mit_klammern.text
    mit_punkt = await client.post(PFAD, json={"name": "BFS.1"}, headers=admin)
    assert mit_punkt.status_code == 200, mit_punkt.text


async def test_doppelter_name_mit_sonderzeichen_wird_trotzdem_erkannt(welt, client):
    """Wörtlicher Vergleich heisst nicht: gar kein Vergleich."""
    admin = await anmelden(client, "admin")
    assert (await client.post(PFAD, json={"name": "IT (neu)"}, headers=admin)).status_code == 200
    doppelt = await client.post(PFAD, json={"name": "it (NEU)"}, headers=admin)
    assert doppelt.status_code == 400
    assert "existiert bereits" in doppelt.json()["detail"]


# --------------------------------------------------------------------------- Umbenennen


async def test_umbenennen_behaelt_die_id_und_damit_alle_zuordnungen(welt, client):
    """Der Grund, warum Bildungsgänge eine eigene Sammlung sind und kein Freitextfeld."""
    await geraet(welt, "a", "bg_meda")
    admin = await anmelden(client, "admin")

    antwort = await client.put(f"{PFAD}/bg_meda", json={"name": "Mediengestaltung"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["id"] == "bg_meda"
    assert antwort.json()["name"] == "Mediengestaltung"

    lehrkraft = await anmelden(client, "schaubach")
    assert await sichtbare_ipads(client, lehrkraft) == ["a"], "Umbenennen darf keine Zuordnung lösen"
    assert aktuelle(await hole(client, admin, "bg_meda")) == {"schaubach"}


async def test_umbenennen_aendert_updated_at_und_laesst_created_at_stehen(welt, client):
    admin = await anmelden(client, "admin")
    vorher = await hole(client, admin, "bg_meda")

    nachher = (await client.put(f"{PFAD}/bg_meda", json={"name": "Mediengestaltung"}, headers=admin)).json()
    assert nachher["created_at"] == vorher["created_at"]
    assert datetime.fromisoformat(nachher["updated_at"]) > datetime.fromisoformat(vorher["updated_at"])


async def test_umbenennen_auf_einen_vergebenen_namen_wird_abgelehnt(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.put(f"{PFAD}/bg_meda", json={"name": "it"}, headers=admin)
    assert antwort.status_code == 400
    assert "existiert bereits" in antwort.json()["detail"]
    assert (await welt.bildungsgaenge.find_one({"id": "bg_meda"}))["name"] == "MEDA"
    assert (await welt.bildungsgaenge.find_one({"id": "bg_it"}))["name"] == "IT"


async def test_umbenennen_auf_die_eigene_schreibweise_ist_erlaubt(welt, client):
    """Der Namensvergleich darf den Bildungsgang nicht mit sich selbst kollidieren lassen."""
    admin = await anmelden(client, "admin")
    antwort = await client.put(f"{PFAD}/bg_meda", json={"name": "Meda"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["name"] == "Meda"


async def test_umbenennen_auf_leeren_namen_wird_abgelehnt(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.put(f"{PFAD}/bg_meda", json={"name": "   "}, headers=admin)
    assert antwort.status_code == 400
    assert (await welt.bildungsgaenge.find_one({"id": "bg_meda"}))["name"] == "MEDA"


async def test_umbenennen_eines_unbekannten_bildungsgangs(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.put(f"{PFAD}/bg_gibtsnicht", json={"name": "Pflege"}, headers=admin)
    assert antwort.status_code == 404


async def test_beschreibung_aendern_laesst_den_namen_unberuehrt(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.put(f"{PFAD}/bg_meda", json={"description": "Dreijährig"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["name"] == "MEDA"
    assert antwort.json()["description"] == "Dreijährig"


# --------------------------------------------------------------------------- Löschen


@pytest.mark.parametrize(
    "sammlung,wort",
    [("ipads", "iPads"), ("students", "Schüler"), ("assignments", "Zuordnungen"), ("contracts", "Verträge")],
)
async def test_loeschen_verweigert_solange_daten_daran_haengen(welt, client, sammlung, wort):
    """Löschen darf niemals Daten mitreissen oder unerreichbar machen.

    Je Sammlung einzeln geprüft: fehlte eine in der Bestandsprüfung, verschwände genau
    deren Inhalt unbemerkt aus der Verwaltung.
    """
    await welt[sammlung].insert_one({"id": "x", "bildungsgang_id": "bg_gym"})
    admin = await anmelden(client, "admin")

    antwort = await client.delete(f"{PFAD}/bg_gym", headers=admin)
    assert antwort.status_code == 400, f"{sammlung} hat das Löschen nicht aufgehalten"
    assert wort in antwort.json()["detail"]
    assert await welt.bildungsgaenge.find_one({"id": "bg_gym"}) is not None
    assert await welt[sammlung].count_documents({}) == 1


async def test_loeschen_erlaubt_wenn_nichts_mehr_daran_haengt(welt, client):
    await geraet(welt, "a", "bg_meda")
    admin = await anmelden(client, "admin")

    antwort = await client.delete(f"{PFAD}/bg_lehrkräfte", headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert "bg_lehrkräfte" not in [b["id"] for b in await liste(client, admin)]
    assert await welt.ipads.count_documents({}) == 1, "Fremde Bestände bleiben unberührt"


async def test_loeschen_nimmt_die_zustaendigkeits_historie_mit(welt, client):
    """Mit dem Bildungsgang verschwindet auch, wer ihn je betreut hat.

    Steht im Widerspruch zur Zusage des Moduls, Zuständigkeiten würden nie gelöscht,
    sondern nur beendet. Hier festgehalten, weil es die einzige Stelle ist, an der ein
    Zuständigkeits-Datensatz verschwindet - und weil es auffallen muss, falls jemand das
    Löschen erlaubt, solange noch Daten daran hängen.
    """
    admin = await anmelden(client, "admin")
    assert await welt.zustaendigkeiten.count_documents({"bildungsgang_id": "bg_gym"}) == 2

    assert (await client.delete(f"{PFAD}/bg_gym", headers=admin)).status_code == 200
    assert await welt.zustaendigkeiten.count_documents({"bildungsgang_id": "bg_gym"}) == 0
    assert await welt.zustaendigkeiten.count_documents({}) == 3, "Fremde Zuständigkeiten bleiben"


async def test_loeschen_eines_unbekannten_bildungsgangs(welt, client):
    admin = await anmelden(client, "admin")
    assert (await client.delete(f"{PFAD}/bg_gibtsnicht", headers=admin)).status_code == 404


async def test_loeschen_zaehlt_den_gesamten_bestand_auf(welt, client):
    """Die Meldung muss sagen, was im Weg steht - sonst sucht der Admin blind."""
    await welt.ipads.insert_many([{"id": "a", "bildungsgang_id": "bg_gym"},
                                  {"id": "b", "bildungsgang_id": "bg_gym"}])
    await welt.students.insert_one({"id": "s", "bildungsgang_id": "bg_gym"})
    admin = await anmelden(client, "admin")

    detail = (await client.delete(f"{PFAD}/bg_gym", headers=admin)).json()["detail"]
    assert "2 iPads" in detail and "1 Schüler" in detail
    assert "GYM" in detail


# --------------------------------------------------------------------- Zuständigkeiten


async def test_neuer_bildungsgang_wird_erst_durch_eine_zustaendigkeit_nutzbar(welt, client):
    """Der ganze Weg in einem Test: anlegen, jemanden eintragen, Zugriff entsteht.

    Und zwar sofort, ohne neue Anmeldung - der Zugriff wird bei jeder Anfrage aus den
    Zuständigkeiten gelesen und steckt nicht im einmal ausgestellten Token.
    """
    admin = await anmelden(client, "admin")
    neu = (await client.post(PFAD, json={"name": "Pflege"}, headers=admin)).json()
    await geraet(welt, "p", neu["id"])

    lehrkraft = await anmelden(client, "bakenecker")
    assert await sichtbare_ipads(client, lehrkraft) == [], "Ein neuer Bildungsgang gehört niemandem"

    antwort = await client.post(
        f"{PFAD}/{neu['id']}/zustaendige", json={"user_id": "u_bakenecker"}, headers=admin
    )
    assert antwort.status_code == 200, antwort.text
    assert await sichtbare_ipads(client, lehrkraft) == ["p"]


async def test_eine_person_kann_mehrere_bildungsgaenge_betreuen(welt, client):
    """Der Grund für den Umbau: schaubach betreut MEDA und IT aus EINEM Konto."""
    await geraet(welt, "a", "bg_meda")
    await geraet(welt, "b", "bg_it")
    await geraet(welt, "c", "bg_gym")
    admin = await anmelden(client, "admin")

    antwort = await client.post(f"{PFAD}/bg_gym/zustaendige", json={"user_id": "u_schaubach"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert "schaubach" in aktuelle(antwort.json())

    lehrkraft = await anmelden(client, "schaubach")
    assert await sichtbare_ipads(client, lehrkraft) == ["a", "b", "c"]


async def test_mehrere_personen_koennen_fuer_einen_bildungsgang_zustaendig_sein(welt, client):
    await geraet(welt, "a", "bg_meda")
    admin = await anmelden(client, "admin")

    antwort = await client.post(f"{PFAD}/bg_meda/zustaendige", json={"user_id": "u_bakenecker"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert aktuelle(antwort.json()) == {"schaubach", "bakenecker"}

    for wer in ["schaubach", "bakenecker"]:
        assert "a" in await sichtbare_ipads(client, await anmelden(client, wer)), wer


async def test_dieselbe_person_kann_nicht_zweimal_eingetragen_werden(welt, client):
    """Ein zweiter laufender Datensatz liesse sich durch einmaliges Beenden nicht beenden."""
    admin = await anmelden(client, "admin")
    antwort = await client.post(f"{PFAD}/bg_meda/zustaendige", json={"user_id": "u_schaubach"}, headers=admin)
    assert antwort.status_code == 400
    assert "bereits zuständig" in antwort.json()["detail"]
    assert await welt.zustaendigkeiten.count_documents(
        {"bildungsgang_id": "bg_meda", "user_id": "u_schaubach", "bis": None}
    ) == 1


async def test_deaktiviertes_konto_kann_nicht_zustaendig_werden(welt, client):
    """Ein deaktiviertes Konto kann sich nicht anmelden - eine Zuständigkeit daran wäre
    ein Bildungsgang, den niemand betreut, der aber betreut aussieht."""
    await welt.users.insert_one({
        "id": "u_ruhe", "username": "ruhe", "password_hash": "x", "role": "user", "is_active": False,
    })
    admin = await anmelden(client, "admin")

    antwort = await client.post(f"{PFAD}/bg_meda/zustaendige", json={"user_id": "u_ruhe"}, headers=admin)
    assert antwort.status_code == 400
    assert "ruhe" in antwort.json()["detail"]
    assert await welt.zustaendigkeiten.count_documents({"user_id": "u_ruhe"}) == 0


async def test_unbekanntes_konto_kann_nicht_zustaendig_werden(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.post(f"{PFAD}/bg_meda/zustaendige", json={"user_id": "u_gibtsnicht"}, headers=admin)
    assert antwort.status_code == 404
    assert await welt.zustaendigkeiten.count_documents({"bildungsgang_id": "bg_meda"}) == 1


async def test_zustaendigkeit_fuer_unbekannten_bildungsgang(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.post(f"{PFAD}/bg_gibtsnicht/zustaendige", json={"user_id": "u_schaubach"}, headers=admin)
    assert antwort.status_code == 404
    assert await welt.zustaendigkeiten.count_documents({"user_id": "u_schaubach"}) == 2


async def test_beenden_entzieht_den_zugriff_und_behaelt_den_datensatz(welt, client):
    """Der Kern der Regel: Zugriff endet sofort, Historie und Daten bleiben."""
    await geraet(welt, "a", "bg_meda")
    await geraet(welt, "b", "bg_it")
    admin = await anmelden(client, "admin")

    antwort = await client.delete(f"{PFAD}/bg_meda/zustaendige/u_schaubach", headers=admin)
    assert antwort.status_code == 200, antwort.text

    datensatz = await welt.zustaendigkeiten.find_one({"id": "z1"})
    assert datensatz is not None, "Zuständigkeiten werden beendet, nicht gelöscht"
    assert datensatz["bis"] is not None

    lehrkraft = await anmelden(client, "schaubach")
    assert await sichtbare_ipads(client, lehrkraft) == ["b"], "MEDA muss sofort weg sein, IT bleibt"
    assert await sichtbare_ipads(client, admin) == ["a", "b"], "Die Geräte selbst bleiben bestehen"


async def test_beendete_zustaendigkeit_bleibt_in_der_historie_sichtbar(welt, client):
    """Nachvollziehbar bleiben muss, wer wann verantwortlich war."""
    admin = await anmelden(client, "admin")
    await client.delete(f"{PFAD}/bg_meda/zustaendige/u_schaubach", headers=admin)

    meda = await hole(client, admin, "bg_meda")
    assert aktuelle(meda) == set()
    assert beendete(meda) == {"schaubach"}


async def test_vorhandene_beendete_zustaendigkeit_wird_mitgeliefert(welt, client):
    """Die ausgeschiedene Person steht weiter bei GYM - mit bis, nicht als aktuell."""
    admin = await anmelden(client, "admin")
    gym = await hole(client, admin, "bg_gym")
    assert aktuelle(gym) == {"bakenecker"}
    assert beendete(gym) == {"ausgeschieden"}


@pytest.mark.xfail(
    reason="_zustaendige sortiert innerhalb der Gruppen nach von AUFSTEIGEND, obwohl der "
    "eigene Kommentar 'nach Beginn absteigend' zusagt. Das vorangestellte sort('von', -1) "
    "aus der Datenbank wird vom anschliessenden sorted() wieder aufgehoben.",
    strict=True,
)
async def test_zustaendige_stehen_je_gruppe_mit_dem_juengsten_beginn_zuerst(welt, client):
    """Aktuelle nach oben, in der Historie der zuletzt Verantwortliche zuerst.

    Wer nach einem Gerät aus 2023 sucht, fragt zuerst den Vorgänger, nicht den von 2019.
    """
    await welt.zustaendigkeiten.insert_many([
        {"id": "h_alt", "bildungsgang_id": "bg_meda", "user_id": "u_bakenecker",
         "von": "2019-08-01T00:00:00+00:00", "bis": "2021-07-31T00:00:00+00:00"},
        {"id": "h_neu", "bildungsgang_id": "bg_meda", "user_id": "u_ausgeschieden",
         "von": "2021-08-01T00:00:00+00:00", "bis": "2023-07-31T00:00:00+00:00"},
    ])
    admin = await anmelden(client, "admin")

    namen = [z["username"] for z in (await hole(client, admin, "bg_meda"))["zustaendige"]]
    assert namen == ["schaubach", "ausgeschieden", "bakenecker"]


async def test_beenden_einer_nicht_bestehenden_zustaendigkeit(welt, client):
    admin = await anmelden(client, "admin")
    antwort = await client.delete(f"{PFAD}/bg_meda/zustaendige/u_bakenecker", headers=admin)
    assert antwort.status_code == 404


async def test_erneutes_beenden_ueberschreibt_das_historische_datum_nicht(welt, client):
    """Sonst wanderte das Austrittsdatum bei jedem Klick auf heute."""
    admin = await anmelden(client, "admin")
    vorher = (await welt.zustaendigkeiten.find_one({"id": "z5"}))["bis"]

    antwort = await client.delete(f"{PFAD}/bg_gym/zustaendige/u_ausgeschieden", headers=admin)
    assert antwort.status_code == 404
    assert (await welt.zustaendigkeiten.find_one({"id": "z5"}))["bis"] == vorher


async def test_wiedereintragen_nach_dem_beenden_legt_einen_neuen_zeitraum_an(welt, client):
    """Rückkehr nach einem Jahr: der alte Zeitraum bleibt, ein neuer kommt dazu."""
    await geraet(welt, "c", "bg_gym")
    admin = await anmelden(client, "admin")

    antwort = await client.post(f"{PFAD}/bg_gym/zustaendige", json={"user_id": "u_ausgeschieden"}, headers=admin)
    assert antwort.status_code == 200, antwort.text
    assert "ausgeschieden" in aktuelle(antwort.json())
    assert "ausgeschieden" in beendete(antwort.json()), "Der alte Zeitraum muss erhalten bleiben"

    assert await welt.zustaendigkeiten.count_documents(
        {"bildungsgang_id": "bg_gym", "user_id": "u_ausgeschieden"}
    ) == 2
    rueckkehrer = await anmelden(client, "ausgeschieden")
    assert await sichtbare_ipads(client, rueckkehrer) == ["c"]
