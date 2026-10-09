"""Anlegen: woher ein neuer Datensatz seinen Bildungsgang bekommt.

Die Zuordnung entsteht beim Anlegen - und nur dort wird sie frei gewählt. Sitzt sie falsch,
ist der Datensatz für die zuständige Person unsichtbar und für eine fremde sichtbar. Genau
so sind die Geräte entstanden, die am admin-Konto hingen statt an einem Bildungsgang.

Deshalb prüfen diese Tests nicht nur, DASS etwas angelegt wird, sondern bei jedem Fall, WO
es landet - und bei jeder Ablehnung, dass wirklich nichts geschrieben wurde.
"""

import pytest

from tests.conftest import anmelden


async def schueler(client, kopf, vorname="Max", nachname="Mustermann", **felder):
    return await client.post(
        "/api/students", json={"sus_vorn": vorname, "sus_nachn": nachname, **felder}, headers=kopf
    )


async def geraet(client, kopf, itnr="IT-100", **felder):
    return await client.post(
        "/api/ipads", json={"itnr": itnr, "snr": f"SN-{itnr}", **felder}, headers=kopf
    )


async def poolgeraet(db, ipad_id, itnr="IT-POOL"):
    await db.ipads.insert_one({
        "id": ipad_id, "bildungsgang_id": None, "is_in_pool": True,
        "itnr": itnr, "snr": f"SN-{itnr}", "status": "ok", "user_id": "u_admin", "pool_history": [],
    })


# --- Vorauswahl aus der Zuständigkeit ------------------------------------------------


async def test_eine_zustaendigkeit_wird_ohne_rueckfrage_uebernommen(welt, client):
    """Der Alltagsfall: wer genau einen Bildungsgang betreut, wird nicht gefragt."""
    kopf = await anmelden(client, "bakenecker")
    antwort = await schueler(client, kopf)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] == "bg_gym"


async def test_mehrere_zustaendigkeiten_erzwingen_eine_wahl(welt, client):
    """Zwei Bildungsgänge, keine Angabe: raten wäre schlimmer als nachfragen."""
    kopf = await anmelden(client, "schaubach")
    antwort = await schueler(client, kopf)
    assert antwort.status_code == 400
    assert await welt.students.count_documents({}) == 0, "Nach einer Rückfrage darf nichts angelegt sein"


async def test_die_rueckfrage_nennt_die_eigenen_und_nur_die_eigenen_bildungsgaenge(welt, client):
    """Die Meldung ist die Auswahlliste. Ein fremder Name darin wäre eine Einladung zum Fehlgriff."""
    kopf = await anmelden(client, "schaubach")
    meldung = (await schueler(client, kopf)).json()["detail"]
    angebotene = sorted(n.strip() for n in meldung.split(":", 1)[1].split(","))
    assert angebotene == ["IT", "MEDA"]


async def test_ausdrueckliche_wahl_schlaegt_die_vorauswahl(welt, client):
    kopf = await anmelden(client, "schaubach")
    antwort = await schueler(client, kopf, bildungsgang_id="bg_it")
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] == "bg_it"


async def test_fremder_bildungsgang_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "schaubach")
    antwort = await schueler(client, kopf, bildungsgang_id="bg_gym")
    assert antwort.status_code == 403
    assert await welt.students.count_documents({}) == 0


async def test_beendete_zustaendigkeit_erlaubt_kein_anlegen_im_alten_bildungsgang(welt, client):
    """Die Historie bleibt, das Schreibrecht nicht. Zugriff hängt an bis=None, sonst an nichts."""
    kopf = await anmelden(client, "ausgeschieden")
    antwort = await schueler(client, kopf, bildungsgang_id="bg_gym")
    assert antwort.status_code == 403
    assert await welt.zustaendigkeiten.count_documents({"user_id": "u_ausgeschieden"}) == 1, \
        "Die beendete Zuständigkeit ist Historie und muss erhalten bleiben"


# --- Die beiden Admin-Fälle, die sich unterscheiden -----------------------------------


async def test_adminkonto_mit_genau_einer_zustaendigkeit_wird_nicht_gefragt(welt, client):
    """wieners ist Admin UND betreut die Lehrkräfte: die Zuständigkeit entscheidet, nicht die Rolle."""
    kopf = await anmelden(client, "wieners")
    antwort = await schueler(client, kopf)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] == "bg_lehrkräfte"


async def test_adminkonto_ohne_zustaendigkeit_muss_waehlen(welt, client):
    """Das Sammelkonto bekommt bewusst keine Vorauswahl - sonst sammelt es wieder alles ein.

    Es betreut selbst keinen Bildungsgang, also kann die Meldung auch keinen anbieten: eine
    Liste aller vier Bildungsgänge wäre genau die Vorauswahl, die hier nicht entstehen soll.
    """
    kopf = await anmelden(client, "admin")
    antwort = await schueler(client, kopf)
    assert antwort.status_code == 400
    meldung = antwort.json()["detail"]
    assert "auswählen" in meldung
    assert not [n for n in ["MEDA", "IT", "GYM", "Lehrkräfte"] if n in meldung]
    assert await welt.students.count_documents({}) == 0


async def test_admin_darf_ausdruecklich_in_jeden_bildungsgang_anlegen(welt, client):
    """Der Admin ist für keinen zuständig und für alle schreibberechtigt - aber nur mit Angabe."""
    kopf = await anmelden(client, "admin")
    antwort = await schueler(client, kopf, bildungsgang_id="bg_gym")
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] == "bg_gym"


# --- Wer gar nichts anlegen darf ------------------------------------------------------


async def test_ohne_zustaendigkeit_verweist_die_meldung_an_die_administration(welt, client):
    """Ohne Zuständigkeit gibt es nichts zu wählen - die Person braucht eine Zuständigkeit,
    keine Auswahlliste. Die Meldung muss sagen, wohin man sich wendet."""
    kopf = await anmelden(client, "ausgeschieden")
    antwort = await schueler(client, kopf)
    assert antwort.status_code == 400
    assert "Administration" in antwort.json()["detail"]


# --- Unbekannte Bildungsgänge ---------------------------------------------------------


async def test_unbekannter_bildungsgang_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await schueler(client, kopf, bildungsgang_id="bg_gibtsnicht")
    assert antwort.status_code == 400
    assert "existiert nicht" in antwort.json()["detail"]
    assert await welt.students.count_documents({}) == 0


async def test_unbekannter_bildungsgang_verraet_einer_lehrkraft_nichts(welt, client):
    """Für eine Lehrkraft sieht ein erfundener Bildungsgang genauso aus wie ein fremder: 403.

    Ein abweichender Status wäre eine Auskunft darüber, welche Bildungsgänge es gibt.
    """
    kopf = await anmelden(client, "schaubach")
    erfunden = await schueler(client, kopf, bildungsgang_id="bg_gibtsnicht")
    fremd = await schueler(client, kopf, nachname="Zweiter", bildungsgang_id="bg_gym")
    assert erfunden.status_code == fremd.status_code == 403


# --- Dieselbe Regel beim Gerät (nur Admins legen Geräte an) ----------------------------


async def test_lehrkraft_darf_keine_geraete_anlegen(welt, client):
    """Der Gerätebestand wird zentral gepflegt - sonst entstehen Karteileichen mit eigener ITNr."""
    kopf = await anmelden(client, "schaubach")
    antwort = await geraet(client, kopf, bildungsgang_id="bg_meda")
    assert antwort.status_code == 403
    assert await welt.ipads.count_documents({}) == 0


async def test_adminkonto_mit_einer_zustaendigkeit_legt_geraet_ohne_rueckfrage_an(welt, client):
    kopf = await anmelden(client, "wieners")
    antwort = await geraet(client, kopf)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] == "bg_lehrkräfte"


async def test_adminkonto_ohne_zustaendigkeit_muss_beim_geraet_waehlen(welt, client):
    kopf = await anmelden(client, "admin")
    antwort = await geraet(client, kopf)
    assert antwort.status_code == 400
    meldung = antwort.json()["detail"]
    assert "auswählen" in meldung
    assert not [n for n in ["MEDA", "IT", "GYM", "Lehrkräfte"] if n in meldung]
    assert await welt.ipads.count_documents({}) == 0


async def test_geraet_ohne_itnr_wird_abgelehnt_bevor_nach_dem_bildungsgang_gefragt_wird(welt, client):
    """Leere Pflichtfelder sind ein Eingabefehler, kein Zuordnungsproblem - die Meldung muss
    das sagen, sonst sucht der Admin den Fehler in der falschen Ecke."""
    kopf = await anmelden(client, "admin")
    antwort = await client.post("/api/ipads", json={"itnr": "", "snr": ""}, headers=kopf)
    assert antwort.status_code == 400
    assert "ITNr" in antwort.json()["detail"]


async def test_angaben_aus_dem_formular_gehen_nicht_verloren(welt, client):
    """Das Anlegemaske schickt sus_str, das Modell heisst sus_str_hnr.

    Pydantic verwirft unbekannte Felder kommentarlos: eine Umbenennung auf einer der beiden
    Seiten wirft die Anschrift still weg, und der Vertrag wird spaeter ohne Adresse gedruckt.
    """
    kopf = await anmelden(client, "bakenecker")
    antwort = await schueler(
        client, kopf, sus_kl="BG1", sus_geb="01.02.2008", sus_str="Hauptstr. 1", sus_ort="Dortmund"
    )
    assert antwort.status_code == 200, antwort.text
    angelegt = antwort.json()
    assert angelegt["sus_str_hnr"] == "Hauptstr. 1"
    assert angelegt["sus_ort"] == "Dortmund"
    assert angelegt["sus_kl"] == "BG1"
    assert angelegt["sus_geb"] == "01.02.2008"


async def test_schueler_ohne_namen_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "bakenecker")
    antwort = await client.post("/api/students", json={"sus_vorn": "", "sus_nachn": ""}, headers=kopf)
    assert antwort.status_code == 400
    assert await welt.students.count_documents({}) == 0


# --- Poolgeräte gehören niemandem ------------------------------------------------------


async def test_poolgeraet_bekommt_keinen_bildungsgang(welt, client):
    """Ein Poolgerät liegt zentral, bis es jemand holt - ohne Rückfrage nach dem Bildungsgang."""
    kopf = await anmelden(client, "admin")
    antwort = await geraet(client, kopf, is_in_pool=True)
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] is None
    assert antwort.json()["is_in_pool"] is True


async def test_poolgeraet_bleibt_auch_mit_angabe_ohne_bildungsgang(welt, client):
    """Eine mitgeschickte Zuordnung darf ein Poolgerät nicht heimlich jemandem zuschlagen."""
    kopf = await anmelden(client, "wieners")
    antwort = await geraet(client, kopf, is_in_pool=True, bildungsgang_id="bg_lehrkräfte")
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["bildungsgang_id"] is None


# --- Dubletten gelten je Bildungsgang --------------------------------------------------


async def test_gleiche_itnr_im_selben_bildungsgang_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "admin")
    assert (await geraet(client, kopf, itnr="IT-100", bildungsgang_id="bg_meda")).status_code == 200
    zweites = await geraet(client, kopf, itnr="IT-100", bildungsgang_id="bg_meda")
    assert zweites.status_code == 400
    assert await welt.ipads.count_documents({"itnr": "IT-100"}) == 1


async def test_gleiche_itnr_in_anderem_bildungsgang_ist_erlaubt(welt, client):
    """Die Eindeutigkeit gilt je Bildungsgang, nicht global: zwei Bildungsgänge führen ihre
    eigenen Nummernkreise und dürfen sich nicht gegenseitig blockieren."""
    kopf = await anmelden(client, "admin")
    assert (await geraet(client, kopf, itnr="IT-100", bildungsgang_id="bg_meda")).status_code == 200
    zweites = await geraet(client, kopf, itnr="IT-100", bildungsgang_id="bg_it")
    assert zweites.status_code == 200, zweites.text
    assert zweites.json()["bildungsgang_id"] == "bg_it"


async def test_gleicher_name_im_selben_bildungsgang_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "bakenecker")
    assert (await schueler(client, kopf)).status_code == 200
    zweiter = await schueler(client, kopf)
    assert zweiter.status_code == 400
    assert await welt.students.count_documents({}) == 1


async def test_gleicher_name_in_anderem_bildungsgang_ist_eine_andere_person(welt, client):
    """Zwei Schüler gleichen Namens in verschiedenen Bildungsgängen sind zwei Menschen."""
    kopf = await anmelden(client, "schaubach")
    erster = await schueler(client, kopf, bildungsgang_id="bg_meda")
    zweiter = await schueler(client, kopf, bildungsgang_id="bg_it")
    assert erster.status_code == 200 and zweiter.status_code == 200, zweiter.text
    assert erster.json()["id"] != zweiter.json()["id"]


async def test_dublettenpruefung_gilt_ueber_konten_hinweg(welt, client):
    """Entscheidend ist der Bildungsgang, nicht wer angelegt hat.

    Legt der Admin denselben Schüler nach, den die zuständige Lehrkraft schon erfasst hat,
    muss das auffallen - sonst steht der Schüler doppelt im selben Bestand.
    """
    kopf_lehrkraft = await anmelden(client, "bakenecker")
    assert (await schueler(client, kopf_lehrkraft)).status_code == 200

    kopf_admin = await anmelden(client, "admin")
    nachtrag = await schueler(client, kopf_admin, bildungsgang_id="bg_gym")
    assert nachtrag.status_code == 400
    assert await welt.students.count_documents({}) == 1


async def test_poolgeraet_verlangt_global_eindeutige_itnr(welt, client):
    """Im Pool gibt es keinen Bildungsgang, der die Nummernkreise trennt - hier muss die ITNr
    global eindeutig sein, sonst lässt sich später nicht sagen, welches Gerät geholt wurde."""
    kopf = await anmelden(client, "admin")
    assert (await geraet(client, kopf, itnr="IT-200", is_in_pool=True)).status_code == 200
    zweites = await geraet(client, kopf, itnr="IT-200", is_in_pool=True)
    assert zweites.status_code == 400
    assert await welt.ipads.count_documents({"itnr": "IT-200"}) == 1


@pytest.mark.xfail(
    reason="BUG: Die globale ITNr-Prüfung greift nur beim Anlegen INS Pool, nicht umgekehrt. "
    "Ein Gerät, das im Pool liegt, lässt sich mit derselben ITNr nochmal direkt in einen "
    "Bildungsgang anlegen - dasselbe physische Gerät steht dann zweimal in der Datenbank.",
    strict=True,
)
async def test_itnr_aus_dem_pool_darf_nicht_nochmal_angelegt_werden(welt, client):
    kopf = await anmelden(client, "admin")
    assert (await geraet(client, kopf, itnr="IT-300", is_in_pool=True)).status_code == 200
    doppelt = await geraet(client, kopf, itnr="IT-300", bildungsgang_id="bg_meda")
    assert doppelt.status_code == 400, "Dasselbe Gerät darf nicht zweimal im Bestand stehen"


@pytest.mark.xfail(
    reason="BUG: Anlegen und Bearbeiten widersprechen sich. Beim Anlegen gilt die ITNr je "
    "Bildungsgang (IT-100 darf in MEDA und IT existieren), beim Bearbeiten prüft "
    "update_ipad global ('ITNr bereits vergeben'). Derselbe Endzustand ist über das "
    "Anlegen erreichbar, über das Korrigieren eines Tippfehlers aber nicht.",
    strict=True,
)
async def test_umbenennen_folgt_derselben_dublettenregel_wie_das_anlegen(welt, client):
    kopf = await anmelden(client, "admin")
    assert (await geraet(client, kopf, itnr="IT-100", bildungsgang_id="bg_meda")).status_code == 200
    zu_korrigieren = await geraet(client, kopf, itnr="IT-900", bildungsgang_id="bg_it")
    assert zu_korrigieren.status_code == 200, zu_korrigieren.text

    korrektur = await client.put(
        f"/api/ipads/{zu_korrigieren.json()['id']}", json={"itnr": "IT-100"}, headers=kopf
    )
    assert korrektur.status_code == 200, korrektur.text


# --- Angelegt-von ist keine Zugehörigkeit ----------------------------------------------


async def test_angelegt_von_vergibt_keine_rechte(welt, client):
    """user_id sagt nur, wer getippt hat. Sichtbar wird der Datensatz über den Bildungsgang.

    Legt der Admin einen Schüler für GYM an, muss ihn die für GYM zuständige Lehrkraft sehen -
    obwohl sie ihn nicht angelegt hat und der Admin nicht für GYM zuständig ist.
    """
    kopf_admin = await anmelden(client, "admin")
    angelegt = await schueler(client, kopf_admin, bildungsgang_id="bg_gym")
    assert angelegt.status_code == 200, angelegt.text
    assert angelegt.json()["user_id"] == "u_admin"

    kopf_lehrkraft = await anmelden(client, "bakenecker")
    sichtbar = await client.get("/api/students", headers=kopf_lehrkraft)
    assert [s["id"] for s in sichtbar.json()] == [angelegt.json()["id"]]


# --- Holen aus dem Pool folgt derselben Regel ------------------------------------------


async def test_adminkonto_muss_beim_holen_aus_dem_pool_waehlen(welt, client):
    """Auch hier entsteht eine Zuordnung - und auch hier darf sie nicht geraten werden."""
    await poolgeraet(welt, "p1")
    kopf = await anmelden(client, "admin")
    antwort = await client.post("/api/ipads/p1/claim", headers=kopf)
    assert antwort.status_code == 400
    assert (await welt.ipads.find_one({"id": "p1"}))["is_in_pool"] is True


async def test_geholtes_geraet_landet_im_bildungsgang_nicht_beim_konto(welt, client):
    """Nach dem Holen gehört das Gerät dem Bildungsgang. user_id bleibt, was es war."""
    await poolgeraet(welt, "p1")
    kopf = await anmelden(client, "wieners")
    antwort = await client.post("/api/ipads/p1/claim", headers=kopf)
    assert antwort.status_code == 200, antwort.text

    danach = await welt.ipads.find_one({"id": "p1"})
    assert danach["bildungsgang_id"] == "bg_lehrkräfte"
    assert danach["is_in_pool"] is False
    assert danach["user_id"] == "u_admin", "Das Holen darf das Angelegt-von nicht umschreiben"


async def test_leere_auswahl_beim_sammelholen_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "wieners")
    antwort = await client.post("/api/ipads/bulk-claim", json={"ipad_ids": []}, headers=kopf)
    assert antwort.status_code == 400
