"""Verträge: die empfindlichsten Daten der Anwendung.

In einem Vertrag stehen das PDF selbst und seine form_fields - Anschrift des Schülers sowie
Namen und Anschriften beider Erziehungsberechtigten. Ein Vertrag, der im falschen Bestand
landet oder in einer fremden Übersicht auftaucht, ist deshalb kein Schönheitsfehler.

Zwei Fälle sind hier eigens festgehalten, weil sie schon einmal auftraten (siehe die
Regressionstests weiter unten): die Detailseite eines gleichnamigen Schülers und die
Gerätehistorie bei doppelter ITNr. Beide verknüpfen über Felder, die NICHT eindeutig sind.
"""

import io

import PyPDF2
from PyPDF2.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

from tests.conftest import anmelden


def pdf(felder: dict | None = None) -> bytes:
    """Ein echtes, kleines PDF - bei Bedarf mit AcroForm-Feldern.

    Gebaut statt aus einer Datei gelesen: der Upload prüft Größe, Endung UND den tatsächlichen
    Inhalt per MIME-Erkennung, ein Platzhalter aus ein paar Bytes käme also nie bis zur Logik,
    um die es in diesen Tests geht.
    """
    writer = PyPDF2.PdfWriter()
    writer.add_blank_page(width=200, height=200)

    eintraege = ArrayObject()
    for name, wert in (felder or {}).items():
        feld = DictionaryObject()
        feld.update(
            {
                NameObject("/T"): TextStringObject(name),
                NameObject("/V"): TextStringObject(wert),
                NameObject("/FT"): NameObject("/Tx"),
            }
        )
        eintraege.append(feld)
    writer._root_object.update({NameObject("/AcroForm"): DictionaryObject({NameObject("/Fields"): eintraege})})

    puffer = io.BytesIO()
    writer.write(puffer)
    return puffer.getvalue()


def datei(name: str, felder: dict | None = None) -> list:
    """Upload-Argument für httpx: eine PDF-Datei unter dem Feldnamen `files`."""
    return [("files", (name, pdf(felder), "application/pdf"))]


async def schueler(db, sid, bildungsgang_id, vorn="Max", nachn="Mustermann", klasse="M1"):
    await db.students.insert_one(
        {
            "id": sid,
            "user_id": "u_admin",
            "bildungsgang_id": bildungsgang_id,
            "sus_vorn": vorn,
            "sus_nachn": nachn,
            "sus_kl": klasse,
            "sus_geb": "01.01.2008",
            "sus_str_hnr": "Musterweg 1",
            "sus_plz": "44137",
            "sus_ort": "Dortmund",
        }
    )


async def geraet(db, gid, bildungsgang_id, itnr):
    await db.ipads.insert_one(
        {
            "id": gid,
            "user_id": "u_admin",
            "bildungsgang_id": bildungsgang_id,
            "itnr": itnr,
            "snr": f"SN-{gid}",
            "typ": "iPad 9",
            "status": "ok",
            "is_in_pool": False,
        }
    )


async def zuordnung(
    db, aid, bildungsgang_id, student_id, ipad_id, itnr, student_name="Max Mustermann", contract_id=None
):
    await db.assignments.insert_one(
        {
            "id": aid,
            "user_id": "u_admin",
            "bildungsgang_id": bildungsgang_id,
            "student_id": student_id,
            "ipad_id": ipad_id,
            "itnr": itnr,
            "student_name": student_name,
            "is_active": True,
            "assigned_at": "2026-02-01T00:00:00+00:00",
            "contract_id": contract_id,
        }
    )


async def vertrag(db, cid, bildungsgang_id, **abweichend):
    """Ein fertiger Vertrag in der Datenbank - für alles, was keinen Upload prüft."""
    daten = {
        "id": cid,
        "user_id": "u_admin",
        "bildungsgang_id": bildungsgang_id,
        "assignment_id": None,
        "ipad_id": None,
        "student_id": None,
        "itnr": None,
        "student_name": None,
        "filename": f"{cid}.pdf",
        "file_data": pdf(),
        "form_fields": {},
        "uploaded_at": "2026-02-01T00:00:00+00:00",
        "is_active": True,
    }
    daten.update(abweichend)
    await db.contracts.insert_one(daten)


# --------------------------------------------------------------------------------------
# Zugehörigkeit: der Vertrag erbt sie von seiner Zuordnung
# --------------------------------------------------------------------------------------


async def test_vertrag_erbt_bildungsgang_der_zuordnung(welt, client):
    """Hochgeladen vom Admin, der für keinen Bildungsgang zuständig ist.

    Entscheidend ist, dass der Vertrag trotzdem im Bestand der Zuordnung landet: die für GYM
    zuständige Lehrkraft muss ihn anschließend herunterladen können. Käme die Zugehörigkeit vom
    Hochladenden, hinge der Vertrag an einem Konto ohne Bildungsgang - sichtbar nur für Admins,
    und Vertrags-PDFs gibt es nirgends sonst.
    """
    await schueler(welt, "s_gym", "bg_gym")
    await geraet(welt, "g_gym", "bg_gym", "IT-900")
    await zuordnung(welt, "a_gym", "bg_gym", "s_gym", "g_gym", "IT-900")

    kopf_admin = await anmelden(client, "admin")
    hochgeladen = await client.post(
        "/api/assignments/a_gym/upload-contract",
        files={"file": ("vertrag.pdf", pdf(), "application/pdf")},
        headers=kopf_admin,
    )
    assert hochgeladen.status_code == 200, hochgeladen.text
    vertrag_id = hochgeladen.json()["contract_id"]

    kopf_gym = await anmelden(client, "bakenecker")
    geladen = await client.get(f"/api/contracts/{vertrag_id}/download", headers=kopf_gym)
    assert geladen.status_code == 200, "Zuständige Lehrkraft kommt nicht an den eigenen Vertrag"


async def test_vertrag_folgt_der_zuordnung_nicht_dem_hochlader(welt, client):
    """schaubach betreut MEDA UND IT - der Vertrag muss zum Bildungsgang der Zuordnung.

    Das ist der Fall, für den es keinen sichtbaren Unterschied gibt, solange alles gutgeht: die
    hochladende Person sieht beide Bestände. Erst wenn eine Zuständigkeit endet oder der Bestand
    übergeben wird, entscheidet sich, ob der Vertrag beim Schüler geblieben ist. Deshalb hier
    ausnahmsweise direkt auf dem Feld geprüft, das die Zugehörigkeit trägt.
    """
    await schueler(welt, "s_it", "bg_it")
    await geraet(welt, "g_it", "bg_it", "IT-100")
    await zuordnung(welt, "a_it", "bg_it", "s_it", "g_it", "IT-100")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post(
        "/api/assignments/a_it/upload-contract",
        files={"file": ("vertrag.pdf", pdf(), "application/pdf")},
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text

    gespeichert = await welt.contracts.find_one({"id": antwort.json()["contract_id"]})
    assert gespeichert["bildungsgang_id"] == "bg_it"
    assert gespeichert["user_id"] == "u_schaubach", "angelegt-von muss erhalten bleiben"


async def test_zuweisung_zieht_vertrag_in_den_bildungsgang_der_zuordnung(welt, client):
    """Ein zunächst unzugeordneter Vertrag zieht mit der Zuordnung um, der er zugewiesen wird."""
    await schueler(welt, "s_it", "bg_it")
    await geraet(welt, "g_it", "bg_it", "IT-100")
    await zuordnung(welt, "a_it", "bg_it", "s_it", "g_it", "IT-100")
    await vertrag(welt, "c_lose", "bg_meda", is_active=False)

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/c_lose/assign/a_it", headers=kopf)
    assert antwort.status_code == 200, antwort.text

    gespeichert = await welt.contracts.find_one({"id": "c_lose"})
    assert gespeichert["bildungsgang_id"] == "bg_it", "Vertrag hängt im alten Bestand fest"
    assert gespeichert["student_id"] == "s_it"
    assert gespeichert["is_active"] is True


async def test_zuweisung_an_fremde_zuordnung_wird_verweigert(welt, client):
    await schueler(welt, "s_gym", "bg_gym")
    await geraet(welt, "g_gym", "bg_gym", "IT-900")
    await zuordnung(welt, "a_gym", "bg_gym", "s_gym", "g_gym", "IT-900")
    await vertrag(welt, "c_meda", "bg_meda", is_active=False)

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/c_meda/assign/a_gym", headers=kopf)
    assert antwort.status_code == 403

    unveraendert = await welt.contracts.find_one({"id": "c_meda"})
    assert unveraendert["assignment_id"] is None


# --------------------------------------------------------------------------------------
# Stapel-Upload: Zuordnung automatisch, sonst Bildungsgang wählen
# --------------------------------------------------------------------------------------


async def test_automatische_zuordnung_ueber_itnr_erbt_den_bildungsgang(welt, client):
    await schueler(welt, "s_it", "bg_it")
    await geraet(welt, "g_it", "bg_it", "IT-100")
    await zuordnung(welt, "a_it", "bg_it", "s_it", "g_it", "IT-100")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post(
        "/api/contracts/upload-multiple",
        files=datei("beliebig.pdf", {"ITNr": "IT-100", "SuSVorn": "Max", "SuSNachn": "Mustermann"}),
        headers=kopf,
    )
    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["results"][0]["status"] == "assigned", antwort.json()["results"]

    gespeichert = await welt.contracts.find_one({"assignment_id": "a_it"})
    assert gespeichert["bildungsgang_id"] == "bg_it"
    aktualisiert = await welt.assignments.find_one({"id": "a_it"})
    assert aktualisiert["contract_id"] == gespeichert["id"], "Rückverweis fehlt"


async def test_itnr_eines_fremden_bildungsgangs_zieht_keine_zuordnung_an(welt, client):
    """Die ITNr ist nur je Bildungsgang eindeutig.

    Ein Vertrag mit der ITNr eines fremden Geräts darf sich nicht an dessen Zuordnung hängen -
    sonst stünde die Anschrift eines fremden Schülers unter einer fremden Zuordnung.
    """
    await schueler(welt, "s_gym", "bg_gym")
    await geraet(welt, "g_gym", "bg_gym", "IT-900")
    await zuordnung(welt, "a_gym", "bg_gym", "s_gym", "g_gym", "IT-900")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post(
        "/api/contracts/upload-multiple",
        files=datei("beliebig.pdf", {"ITNr": "IT-900", "SuSVorn": "Max", "SuSNachn": "Mustermann"}),
        headers=kopf,
    )
    assert antwort.status_code == 200
    assert antwort.json()["results"][0]["status"] != "assigned"
    assert await welt.contracts.count_documents({"assignment_id": "a_gym"}) == 0
    unberuehrt = await welt.assignments.find_one({"id": "a_gym"})
    assert unberuehrt["contract_id"] is None


async def test_unzuordenbarer_vertrag_verlangt_vom_admin_eine_wahl(welt, client):
    """Der Admin betreut selbst keinen Bildungsgang - ohne Angabe gibt es keine Vorauswahl.

    Lieber eine Rückfrage als ein Vertrag, der unbemerkt im falschen Bestand landet.
    """
    kopf = await anmelden(client, "admin")
    antwort = await client.post("/api/contracts/upload-multiple", files=datei("ohne_zuordnung.pdf"), headers=kopf)
    assert antwort.status_code == 200
    ergebnis = antwort.json()["results"][0]
    assert ergebnis["status"] == "error"
    assert "Bildungsgang auswählen" in ergebnis["message"], ergebnis["message"]
    assert await welt.contracts.count_documents({}) == 0, "Vertrag darf nicht blind entstehen"


async def test_unzuordenbarer_vertrag_landet_im_gewaehlten_bildungsgang(welt, client):
    kopf_admin = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/contracts/upload-multiple",
        files=datei("ohne_zuordnung.pdf"),
        data={"bildungsgang_id": "bg_gym"},
        headers=kopf_admin,
    )
    assert antwort.json()["results"][0]["status"] == "unassigned", antwort.json()["results"]

    kopf_gym = await anmelden(client, "bakenecker")
    sichtbar = await client.get("/api/contracts/unassigned", headers=kopf_gym)
    assert [c["filename"] for c in sichtbar.json()] == ["ohne_zuordnung.pdf"]

    kopf_fremd = await anmelden(client, "schaubach")
    unsichtbar = await client.get("/api/contracts/unassigned", headers=kopf_fremd)
    assert unsichtbar.json() == []


async def test_upload_in_fremden_bildungsgang_wird_abgelehnt(welt, client):
    kopf = await anmelden(client, "schaubach")
    antwort = await client.post(
        "/api/contracts/upload-multiple",
        files=datei("ohne_zuordnung.pdf"),
        data={"bildungsgang_id": "bg_gym"},
        headers=kopf,
    )
    ergebnis = antwort.json()["results"][0]
    assert ergebnis["status"] == "error"
    assert "nicht zuständig" in ergebnis["message"], ergebnis["message"]
    assert await welt.contracts.count_documents({}) == 0


async def test_zuordnung_aus_altbestand_erbt_den_bildungsgang_des_schuelers(welt, client):
    """Zuordnung ohne Bildungsgang: der Vertrag soll den des Schülers übernehmen."""
    await schueler(welt, "s_alt", "bg_gym")
    await geraet(welt, "g_alt", "bg_gym", "IT-700")
    await zuordnung(welt, "a_alt", None, "s_alt", "g_alt", "IT-700")

    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/contracts/upload-multiple",
        files=datei("beliebig.pdf", {"ITNr": "IT-700", "SuSVorn": "Max", "SuSNachn": "Mustermann"}),
        headers=kopf,
    )
    assert antwort.json()["results"][0]["status"] == "assigned", antwort.json()["results"]
    gespeichert = await welt.contracts.find_one({"assignment_id": "a_alt"})
    assert gespeichert["bildungsgang_id"] == "bg_gym"


async def test_zuordnung_ohne_bildungsgang_meldet_fehlende_zugehoerigkeit(welt, client):
    """Eine bewusst ausgelöste 400 muss als 400 ankommen - sie sagt, was zu tun ist."""
    await schueler(welt, "s_alt", "bg_gym")
    await geraet(welt, "g_alt", "bg_gym", "IT-700")
    await zuordnung(welt, "a_alt", None, "s_alt", "g_alt", "IT-700")

    kopf = await anmelden(client, "admin")
    antwort = await client.post(
        "/api/assignments/a_alt/upload-contract",
        files={"file": ("vertrag.pdf", pdf(), "application/pdf")},
        headers=kopf,
    )
    assert antwort.status_code == 400, antwort.text


# --------------------------------------------------------------------------------------
# Sichtbarkeit und Download
# --------------------------------------------------------------------------------------


async def test_download_eines_fremden_vertrags_wird_verweigert(welt, client):
    """403 statt Datei - im PDF stehen Anschriften von Schüler und Erziehungsberechtigten."""
    await vertrag(welt, "c_meda", "bg_meda")

    kopf_fremd = await anmelden(client, "bakenecker")
    assert (await client.get("/api/contracts/c_meda/download", headers=kopf_fremd)).status_code == 403
    assert (await client.get("/api/contracts/c_meda", headers=kopf_fremd)).status_code == 403

    kopf_eigen = await anmelden(client, "schaubach")
    eigen = await client.get("/api/contracts/c_meda/download", headers=kopf_eigen)
    assert eigen.status_code == 200
    assert eigen.content.startswith(b"%PDF")


async def test_beendete_zustaendigkeit_entzieht_den_download(welt, client):
    """ausgeschieden war für GYM zuständig - die Historie bleibt, der Zugriff endet."""
    await vertrag(welt, "c_gym", "bg_gym")
    kopf = await anmelden(client, "ausgeschieden")
    assert (await client.get("/api/contracts/c_gym/download", headers=kopf)).status_code == 403


async def test_ohne_anmeldung_kein_download(welt, client):
    await vertrag(welt, "c_meda", "bg_meda")
    assert (await client.get("/api/contracts/c_meda/download")).status_code == 401


async def test_vertragsliste_zeigt_nur_die_eigenen_bildungsgaenge(welt, client):
    await vertrag(welt, "c_meda", "bg_meda")
    await vertrag(welt, "c_it", "bg_it")
    await vertrag(welt, "c_gym", "bg_gym")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.get("/api/contracts", headers=kopf)
    assert sorted(c["id"] for c in antwort.json()) == ["c_it", "c_meda"]


# --------------------------------------------------------------------------------------
# Regression: zwei Verknüpfungen über NICHT eindeutige Felder
# --------------------------------------------------------------------------------------


async def test_detailseite_zeigt_keine_vertraege_eines_gleichnamigen_schuelers(welt, client):
    """REGRESSION: Die Detailseite sucht Verträge auch über 'Vorname Nachname'.

    Derselbe Name existiert in verschiedenen Bildungsgängen. Ohne Besitzerfilter erschienen auf
    der Seite des eigenen Schülers die Verträge des fremden Namensvetters - samt Dateiname und
    ITNr des fremden Bestands.
    """
    await schueler(welt, "s_meda", "bg_meda", vorn="Max", nachn="Mustermann")
    await schueler(welt, "s_gym", "bg_gym", vorn="Max", nachn="Mustermann")
    await vertrag(welt, "c_meda", "bg_meda", student_id="s_meda", student_name="Max Mustermann")
    await vertrag(
        welt,
        "c_gym",
        "bg_gym",
        student_id="s_gym",
        student_name="Max Mustermann",
        filename="GYM_Geheim.pdf",
        itnr="IT-900",
    )

    kopf = await anmelden(client, "schaubach")
    antwort = await client.get("/api/students/s_meda", headers=kopf)
    assert antwort.status_code == 200
    assert [c["id"] for c in antwort.json()["contracts"]] == ["c_meda"]
    assert "GYM_Geheim" not in antwort.text


async def test_geraetehistorie_zeigt_keine_fremden_vertraege_mit_gleicher_itnr(welt, client):
    """REGRESSION: Die Historie sucht Verträge auch über die ITNr.

    Die ITNr ist nur je Bildungsgang eindeutig. Ohne Besitzerfilter lieferte die Historie des
    eigenen Geräts die form_fields eines fremden Vertrags mit - darin Anschrift des Schülers
    sowie Namen und Anschriften beider Erziehungsberechtigten.
    """
    await geraet(welt, "g_meda", "bg_meda", "IT-500")
    await geraet(welt, "g_gym", "bg_gym", "IT-500")
    await vertrag(welt, "c_meda", "bg_meda", ipad_id="g_meda", itnr="IT-500")
    await vertrag(
        welt,
        "c_gym",
        "bg_gym",
        ipad_id="g_gym",
        itnr="IT-500",
        filename="GYM_Geheim.pdf",
        form_fields={"SuSStrHnr": "Geheimweg 1", "Erz1Nachn": "Fremdeltern"},
    )

    kopf = await anmelden(client, "schaubach")
    antwort = await client.get("/api/ipads/g_meda/history", headers=kopf)
    assert antwort.status_code == 200
    assert [c["id"] for c in antwort.json()["contracts"]] == ["c_meda"]
    assert "Geheimweg" not in antwort.text
    assert "Fremdeltern" not in antwort.text


# --------------------------------------------------------------------------------------
# Obergrenze je Schüler
# --------------------------------------------------------------------------------------


async def vertraege_fuer(db, student_id, bildungsgang_id, anzahl, is_active=True):
    for n in range(anzahl):
        await vertrag(
            db,
            f"c_{student_id}_{n}",
            bildungsgang_id,
            student_id=student_id,
            student_name="Max Mustermann",
            is_active=is_active,
        )


async def test_vierter_vertrag_fuer_denselben_schueler_wird_abgelehnt(welt, client):
    """Drei Verträge je Schüler sind das Maximum (MAX_CONTRACTS_PER_STUDENT)."""
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100")
    await vertraege_fuer(welt, "s_meda", "bg_meda", 3)
    await vertrag(welt, "c_neu", "bg_meda", is_active=False)

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/c_neu/assign/a_meda", headers=kopf)
    assert antwort.status_code == 400
    assert "Maximum" in antwort.json()["detail"], antwort.text

    unveraendert = await welt.contracts.find_one({"id": "c_neu"})
    assert unveraendert["assignment_id"] is None


async def test_ersetzte_vertraege_zaehlen_nicht_gegen_die_obergrenze(welt, client):
    """Ein beim Neu-Hochladen auf inaktiv gesetzter Vertrag darf nicht dauerhaft blockieren."""
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100")
    await vertraege_fuer(welt, "s_meda", "bg_meda", 3, is_active=False)
    await vertrag(welt, "c_neu", "bg_meda", is_active=False)

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/c_neu/assign/a_meda", headers=kopf)
    assert antwort.status_code == 200, antwort.text


async def test_obergrenze_zaehlt_auch_unsichtbare_vertraege(welt, client):
    """Gezählt wird, was der Schüler hat - nicht, was der Aufrufer davon sehen darf.

    Ein Vertrag aus Altbestand ohne Bildungsgang zählt mit. Zählte man nur die sichtbaren,
    ließe sich die Obergrenze durch solche Datensätze überschreiten.
    """
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100")
    await vertraege_fuer(welt, "s_meda", "bg_meda", 2)
    await vertrag(welt, "c_altbestand", None, student_id="s_meda", student_name="Max Mustermann")
    await vertrag(welt, "c_neu", "bg_meda", is_active=False)

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/c_neu/assign/a_meda", headers=kopf)
    assert antwort.status_code == 400, "Unsichtbarer Vertrag wurde nicht mitgezählt"


async def test_schueler_am_limit_wird_nicht_mehr_zur_auswahl_angeboten(welt, client):
    await schueler(welt, "s_voll", "bg_meda")
    await schueler(welt, "s_frei", "bg_meda", vorn="Lea", nachn="Beispiel")
    await geraet(welt, "g_voll", "bg_meda", "IT-100")
    await geraet(welt, "g_frei", "bg_meda", "IT-101")
    await zuordnung(welt, "a_voll", "bg_meda", "s_voll", "g_voll", "IT-100")
    await zuordnung(welt, "a_frei", "bg_meda", "s_frei", "g_frei", "IT-101", "Lea Beispiel")
    await vertraege_fuer(welt, "s_voll", "bg_meda", 3)

    kopf = await anmelden(client, "schaubach")
    antwort = await client.get("/api/assignments/available-for-contracts", headers=kopf)
    assert [a["assignment_id"] for a in antwort.json()] == ["a_frei"]


async def test_auswahl_beruecksichtigt_auch_unsichtbare_vertraege(welt, client):
    """Die Auswahl zählt wie die Zuweisung - sonst wird angeboten, was danach scheitert."""
    await schueler(welt, "s_voll", "bg_meda")
    await geraet(welt, "g_voll", "bg_meda", "IT-100")
    await zuordnung(welt, "a_voll", "bg_meda", "s_voll", "g_voll", "IT-100")
    await vertraege_fuer(welt, "s_voll", "bg_meda", 2)
    await vertrag(welt, "c_altbestand", None, student_id="s_voll", student_name="Max Mustermann")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.get("/api/assignments/available-for-contracts", headers=kopf)
    assert antwort.json() == []


# --------------------------------------------------------------------------------------
# Löschen
# --------------------------------------------------------------------------------------


async def test_fremder_vertrag_laesst_sich_nicht_loeschen(welt, client):
    await vertrag(welt, "c_gym", "bg_gym")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.delete("/api/contracts/c_gym", headers=kopf)
    assert antwort.status_code == 403
    assert await welt.contracts.count_documents({"id": "c_gym"}) == 1


async def test_stapelloeschung_laesst_fremde_vertraege_stehen(welt, client):
    """Eine Liste von IDs darf nicht zum Schlupfloch um die Rechteprüfung herum werden."""
    await vertrag(welt, "c_meda", "bg_meda")
    await vertrag(welt, "c_gym", "bg_gym")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/batch-delete", json={"contract_ids": ["c_meda", "c_gym"]}, headers=kopf)
    assert antwort.status_code == 200
    assert antwort.json()["deleted_count"] == 1
    assert [f["contract_id"] for f in antwort.json()["errors"]] == ["c_gym"]
    assert await welt.contracts.count_documents({"id": "c_gym"}) == 1
    assert await welt.contracts.count_documents({"id": "c_meda"}) == 0


async def test_leere_stapelloeschung_wird_abgewiesen(welt, client):
    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/contracts/batch-delete", json={"contract_ids": []}, headers=kopf)
    assert antwort.status_code == 400


async def test_geloeschter_vertrag_gibt_die_zuordnung_wieder_frei(welt, client):
    """Danach muss sich der Zuordnung ein neuer Vertrag zuweisen lassen - sonst ist sie blockiert."""
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100", contract_id="c_alt")
    await vertrag(welt, "c_alt", "bg_meda", assignment_id="a_meda", student_id="s_meda")

    kopf = await anmelden(client, "schaubach")
    assert (await client.delete("/api/contracts/c_alt", headers=kopf)).status_code == 200

    freigegeben = await welt.assignments.find_one({"id": "a_meda"})
    assert freigegeben["contract_id"] is None


async def test_vertragserstellung_ohne_auswahl_wird_abgewiesen(welt, client):
    """Eine leere Auswahl hieß früher "alle offenen Zuordnungen" - ein Fehlklick genügte."""
    await schueler(welt, "s_meda", "bg_meda")
    await geraet(welt, "g_meda", "bg_meda", "IT-100")
    await zuordnung(welt, "a_meda", "bg_meda", "s_meda", "g_meda", "IT-100")

    kopf = await anmelden(client, "admin")
    leer = await client.post("/api/assignments/generate-contracts", json={"assignment_ids": []}, headers=kopf)
    assert leer.status_code == 400
    ohne = await client.post("/api/assignments/generate-contracts", json={}, headers=kopf)
    assert ohne.status_code == 400
    # Die alten Namensfilter als Query-Parameter öffnen keinen Hintertürweg mehr.
    gefiltert = await client.post("/api/assignments/generate-contracts?sus_nachn=Mustermann", json={}, headers=kopf)
    assert gefiltert.status_code == 400
    assert await welt.contracts.count_documents({}) == 0


async def test_vertragserstellung_fuer_fremde_auswahl_findet_nichts(welt, client):
    await schueler(welt, "s_gym", "bg_gym")
    await geraet(welt, "g_gym", "bg_gym", "IT-200")
    await zuordnung(welt, "a_gym", "bg_gym", "s_gym", "g_gym", "IT-200")

    kopf = await anmelden(client, "schaubach")
    antwort = await client.post("/api/assignments/generate-contracts", json={"assignment_ids": ["a_gym"]}, headers=kopf)
    assert antwort.status_code == 404
    assert await welt.contracts.count_documents({}) == 0
