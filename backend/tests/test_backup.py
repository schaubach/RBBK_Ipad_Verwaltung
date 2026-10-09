"""Datensicherung: Export, Wiederherstellung, Verschlüsselung und Aufräumen.

Ein Backup dieser Anwendung enthält den gesamten Schülerbestand samt der unterschriebenen
Leihverträge als PDF - also Namen, Adressen und Unterschriften von Schülern und Eltern.
Ein unverschlüsselt entstandenes Backup ist deshalb schlimmer als gar keines, und ein Backup,
das beim Zurückspielen die Zuständigkeiten verliert, ist keine Wiederherstellung.

Getestet wird über die HTTP-Endpunkte. Der Tagesjob hat keinen eigenen Endpunkt; wo er
gemeint ist, steht es im jeweiligen Docstring.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from core.crypto import is_encrypted_backup
from routes.backup import SERVER_BACKUP_KEEP_MINIMUM, save_server_backup
from tests.conftest import anmelden

PDF_INHALT = b"%PDF-1.4 Leihvertrag Erika Mustermann, unterschrieben"


@pytest.fixture(autouse=True)
def backup_verzeichnisse(tmp_path, monkeypatch):
    """Dateikopien in ein Wegwerfverzeichnis umlenken.

    Im Container zeigen beide Pfade auf echte Backup-Verzeichnisse - ``/app/backups`` ist vom
    Host gemountet und wird von dort ausser Haus synchronisiert. Ohne diese Umlenkung würden
    die Tests dort hineinschreiben und beim Aufräumen echte Sicherungen löschen.
    """
    import routes.backup as backup

    server_verzeichnis = tmp_path / "server"
    monkeypatch.setattr(backup, "SERVER_BACKUP_FILE_DIR", server_verzeichnis)
    monkeypatch.setattr(backup, "PRE_RESTORE_BACKUPS_DIR", tmp_path / "pre_restore")
    return server_verzeichnis


async def passwort_setzen(client, kopf, passwort="Backup-Passwort-123"):
    antwort = await client.put("/api/settings/backup-encryption", json={"password": passwort}, headers=kopf)
    assert antwort.status_code == 200, antwort.text


async def datenbestand(db):
    """Ein kleiner, aber vollständiger Bestand über alle gesicherten Sammlungen hinweg."""
    await db.students.insert_one({
        "id": "s1", "name": "Mustermann", "vorname": "Erika",
        "bildungsgang_id": "bg_meda", "user_id": "u_schaubach",
    })
    await db.ipads.insert_one({
        "id": "i1", "itnr": "IT-1", "snr": "SN-1", "status": "ok",
        "bildungsgang_id": "bg_meda", "is_in_pool": False, "user_id": "u_schaubach",
    })
    await db.assignments.insert_one({
        "id": "a1", "student_id": "s1", "ipad_id": "i1", "itnr": "IT-1", "is_active": True,
        "bildungsgang_id": "bg_meda", "user_id": "u_schaubach",
        "assigned_at": datetime(2026, 2, 1, 8, 0, tzinfo=timezone.utc),
    })
    await db.contracts.insert_one({
        "id": "v1", "assignment_id": "a1", "student_id": "s1", "ipad_id": "i1",
        "student_name": "Erika Mustermann", "filename": "vertrag_mustermann.pdf",
        "file_data": PDF_INHALT, "bildungsgang_id": "bg_meda", "user_id": "u_schaubach",
    })


async def wiederherstellen(client, kopf, inhalt: bytes, dateiname="backup.json.enc"):
    return await client.post(
        "/api/backup/import",
        headers=kopf,
        files={"file": (dateiname, inhalt, "application/octet-stream")},
    )


async def altes_serverbackup(db, tage: int) -> str:
    """Ein Server-Backup, das vor ``tage`` Tagen entstanden ist, direkt in GridFS ablegen."""
    bucket = AsyncIOMotorGridFSBucket(db, bucket_name="backups")
    datei_id = await bucket.upload_from_stream(
        f"rbbk_ipad_verwaltung_backup_alt-{tage:04d}.json.enc", b"alter Inhalt",
        metadata={"encrypted": True},
    )
    await db["backups.files"].update_one(
        {"_id": datei_id},
        {"$set": {"uploadDate": datetime.now(timezone.utc) - timedelta(days=tage)}},
    )
    return str(datei_id)


# --- Ohne Backup-Passwort darf nichts entstehen ------------------------------------------

async def test_ohne_backup_passwort_entsteht_kein_download(welt, client):
    """Schülerdaten dürfen den Server nicht unverschlüsselt verlassen - lieber kein Backup."""
    kopf = await anmelden(client, "admin")
    await datenbestand(welt)

    antwort = await client.get("/api/backup/export", headers=kopf)

    assert antwort.status_code == 400
    assert "Backup-Passwort" in antwort.json()["detail"]
    assert PDF_INHALT not in antwort.content


async def test_ohne_backup_passwort_entsteht_kein_serverbackup(welt, client):
    kopf = await anmelden(client, "admin")
    await datenbestand(welt)

    antwort = await client.post("/api/backup/server-backups/run-now", headers=kopf)

    assert antwort.status_code == 400
    assert "Backup-Passwort" in antwort.json()["detail"]
    assert (await client.get("/api/backup/server-backups", headers=kopf)).json() == []


async def test_backup_passwort_muss_lang_genug_sein(welt, client):
    kopf = await anmelden(client, "admin")

    antwort = await client.put("/api/settings/backup-encryption", json={"password": "kurz"}, headers=kopf)

    assert antwort.status_code == 400
    assert (await client.get("/api/settings/backup-encryption", headers=kopf)).json() == {
        "password_configured": False
    }


async def test_lehrkraft_bekommt_kein_backup(welt, client):
    """Ein Backup enthält jeden Bildungsgang. Wer nur einen betreut, darf es nicht ziehen."""
    admin_kopf = await anmelden(client, "admin")
    await passwort_setzen(client, admin_kopf)
    await datenbestand(welt)

    kopf = await anmelden(client, "schaubach")
    assert (await client.get("/api/backup/export", headers=kopf)).status_code == 403
    assert (await client.get("/api/backup/server-backups", headers=kopf)).status_code == 403
    assert (await wiederherstellen(client, kopf, b"egal")).status_code == 403


# --- Verschlüsselung ----------------------------------------------------------------------

async def test_export_verlaesst_den_server_nur_verschluesselt(welt, client):
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    antwort = await client.get("/api/backup/export", headers=kopf)

    assert antwort.status_code == 200
    assert is_encrypted_backup(antwort.content)
    assert b"Mustermann" not in antwort.content, "Klarnamen dürfen nicht in der Datei stehen"
    assert PDF_INHALT not in antwort.content


async def test_zwei_backups_desselben_bestands_sind_byteweise_verschieden(welt, client):
    """Begründung für die Prüfsumme über den Klartext: jede Verschlüsselung zieht frischen
    Salt und IV. Zwei Sicherungen desselben Bestands sehen deshalb völlig unterschiedlich aus
    (bei gleicher Länge) - am verschlüsselten Inhalt ist keine Entdoppelung möglich.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    erste = (await client.get("/api/backup/export", headers=kopf)).content
    zweite = (await client.get("/api/backup/export", headers=kopf)).content

    assert erste != zweite
    assert len(erste) == len(zweite)


async def test_falsches_backup_passwort_wird_verstaendlich_abgelehnt(welt, client):
    """Nach einem Passwortwechsel ist ein älteres Backup nicht mehr lesbar. Steht das nicht in
    der Meldung, sucht man den Fehler in der Datei statt im Passwort.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf, "Erstes-Passwort-123")
    await datenbestand(welt)
    sicherung = (await client.get("/api/backup/export", headers=kopf)).content
    await passwort_setzen(client, kopf, "Zweites-Passwort-456")

    antwort = await wiederherstellen(client, kopf, sicherung)

    assert antwort.status_code == 400
    assert "Passwort" in antwort.json()["detail"]
    assert await welt.students.count_documents({}) == 1, "Ein abgelehnter Import darf nichts anfassen"


async def test_import_lehnt_fremdes_dateiformat_ab(welt, client):
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    antwort = await wiederherstellen(client, kopf, b"PK\x03\x04", dateiname="backup.zip")

    assert antwort.status_code == 400
    assert await welt.students.count_documents({}) == 1


# --- Hin und zurück ------------------------------------------------------------------------

async def test_wiederherstellung_bringt_alle_sammlungen_zurueck(welt, client):
    """Der vollständige Weg: verschlüsselt exportieren, alles verlieren, zurückspielen.

    Entscheidend ist der Vertrag: er liegt als PDF im Dokument und muss Byte für Byte
    zurückkommen, sonst ist die Unterschrift weg.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    zuordnung_vorher = await welt.assignments.find_one({"id": "a1"})

    sicherung = (await client.get("/api/backup/export", headers=kopf)).content

    for sammlung in ("students", "ipads", "assignments", "contracts"):
        await welt[sammlung].delete_many({})
    await welt.users.insert_one({"id": "u_spaeter", "username": "spaeter", "role": "user", "is_active": True})

    antwort = await wiederherstellen(client, kopf, sicherung)
    assert antwort.status_code == 200, antwort.text

    schueler = await welt.students.find_one({"id": "s1"})
    assert schueler["name"] == "Mustermann"
    assert (await welt.ipads.find_one({"id": "i1"}))["itnr"] == "IT-1"
    assert (await welt.assignments.find_one({"id": "a1"}))["assigned_at"] == zuordnung_vorher["assigned_at"]

    vertrag = await welt.contracts.find_one({"id": "v1"})
    assert bytes(vertrag["file_data"]) == PDF_INHALT, "Das unterschriebene PDF muss unverändert zurückkommen"

    assert await welt.users.find_one({"id": "u_admin"}) is not None
    assert await welt.users.find_one({"id": "u_spaeter"}) is None, \
        "Wiederherstellung stellt den Stand des Backups her, sie ergänzt ihn nicht"
    assert (await client.get("/api/settings/backup-encryption", headers=kopf)).json()["password_configured"] is True


async def test_geraet_gehoert_nach_der_wiederherstellung_demselben_bildungsgang(welt, client):
    """Der Besitz hängt am Bildungsgang. Nach dem Zurückspielen muss schaubach genau sein
    MEDA-Gerät wiedersehen - und weiterhin nicht das des GYM.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    await welt.ipads.insert_one({
        "id": "i_gym", "itnr": "IT-9", "snr": "SN-9", "status": "ok",
        "bildungsgang_id": "bg_gym", "is_in_pool": False, "user_id": "u_bakenecker",
    })

    sicherung = (await client.get("/api/backup/export", headers=kopf)).content
    await welt.ipads.delete_many({})
    assert (await wiederherstellen(client, kopf, sicherung)).status_code == 200

    lehrkraft = await anmelden(client, "schaubach")
    sichtbar = (await client.get("/api/ipads", headers=lehrkraft)).json()
    assert [g["id"] for g in sichtbar] == ["i1"]


async def test_bildungsgaenge_ueberleben_die_wiederherstellung(welt, client):
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    sicherung = (await client.get("/api/backup/export", headers=kopf)).content
    await welt.bildungsgaenge.delete_many({})
    assert (await wiederherstellen(client, kopf, sicherung)).status_code == 200

    namen = sorted(b["name"] for b in await welt.bildungsgaenge.find({}).to_list(length=None))
    assert namen == ["GYM", "IT", "Lehrkräfte", "MEDA"]


async def test_zustaendigkeiten_ueberleben_die_wiederherstellung(welt, client):
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    sicherung = (await client.get("/api/backup/export", headers=kopf)).content
    await welt.zustaendigkeiten.delete_many({})
    assert (await wiederherstellen(client, kopf, sicherung)).status_code == 200

    lehrkraft = await anmelden(client, "schaubach")
    sichtbar = (await client.get("/api/ipads", headers=lehrkraft)).json()
    assert [g["id"] for g in sichtbar] == ["i1"], "Nach der Wiederherstellung muss der Zugriff zurück sein"


async def test_vor_jeder_wiederherstellung_entsteht_ein_sicherheitsnetz(welt, client):
    """Wer das falsche Backup einspielt, soll den vorherigen Stand noch holen können."""
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    sicherung = (await client.get("/api/backup/export", headers=kopf)).content

    antwort = await wiederherstellen(client, kopf, sicherung)
    assert antwort.status_code == 200
    dateiname = antwort.json()["pre_restore_backup"]

    liste = (await client.get("/api/backup/pre-restore-backups", headers=kopf)).json()
    assert [e["filename"] for e in liste] == [dateiname]
    assert liste[0]["encrypted"] is True, "Auch das Sicherheitsnetz enthält Schülerdaten"

    datei = await client.get(f"/api/backup/pre-restore-backups/{dateiname}/download", headers=kopf)
    assert datei.status_code == 200
    assert is_encrypted_backup(datei.content)


async def test_download_gibt_nur_selbst_erzeugte_sicherheitsnetze_heraus(welt, client, backup_verzeichnisse, tmp_path):
    """Der Dateiname kommt von aussen und landet im Dateisystem. Herausgegeben wird nur, was
    dem eigenen Muster entspricht - sonst wäre jede Datei im Verzeichnis lesbar.
    """
    kopf = await anmelden(client, "admin")
    import routes.backup as backup
    backup.PRE_RESTORE_BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    (backup.PRE_RESTORE_BACKUPS_DIR / "geheim.txt").write_bytes(b"nicht fuer den Download")

    fremd = await client.get("/api/backup/pre-restore-backups/geheim.txt/download", headers=kopf)
    assert fremd.status_code == 400
    assert "Dateiname" in fremd.json()["detail"]

    unbekannt = await client.get(
        "/api/backup/pre-restore-backups/pre_restore_backup_20200101_120000.json/download", headers=kopf
    )
    assert unbekannt.status_code == 404


# --- Entdoppelung: unveränderte Daten erzeugen kein neues Backup --------------------------

async def test_pruefsumme_bleibt_bei_unveraendertem_bestand_gleich(welt, client):
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    erste = (await client.post("/api/backup/server-backups/run-now", headers=kopf)).json()
    zweite = (await client.post("/api/backup/server-backups/run-now", headers=kopf)).json()

    assert zweite["payload_sha256"] == erste["payload_sha256"]


async def test_unveraenderter_bestand_erzeugt_kein_neues_tagesbackup(welt, client):
    """Der Tagesjob hat keinen eigenen Endpunkt; er wird hier direkt angestossen. Die Wirkung
    wird über die Liste der Server-Backups geprüft, nicht am Rückgabewert allein.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    ergebnis = await save_server_backup(skip_if_unchanged=True)

    assert ergebnis["skipped"] is True
    assert len((await client.get("/api/backup/server-backups", headers=kopf)).json()) == 1


async def test_veraenderter_bestand_erzeugt_ein_neues_tagesbackup(welt, client):
    """Gegenprobe: kommt ein Gerät dazu, muss gesichert werden."""
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    await welt.ipads.insert_one({
        "id": "i2", "itnr": "IT-2", "snr": "SN-2", "status": "ok",
        "bildungsgang_id": "bg_it", "is_in_pool": False, "user_id": "u_schaubach",
    })
    ergebnis = await save_server_backup(skip_if_unchanged=True)

    assert ergebnis["skipped"] is False
    assert len((await client.get("/api/backup/server-backups", headers=kopf)).json()) == 2


# --- Aufräumen ----------------------------------------------------------------------------

async def test_aufraeumen_behaelt_die_juengsten_serverbackups_unabhaengig_vom_alter(welt, client):
    """Ohne diese Untergrenze gäbe es einen Pfad zu null Backups: entsteht über Wochen nichts
    Neues (Ferien, Entdoppelung), würden die vorhandenen nacheinander wegaltern.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    alte = [await altes_serverbackup(welt, tage) for tage in (400, 300, 200, 100, 50)]

    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    liste = (await client.get("/api/backup/server-backups", headers=kopf)).json()
    ids = [eintrag["id"] for eintrag in liste]
    assert len(ids) == SERVER_BACKUP_KEEP_MINIMUM
    assert ids[0] not in alte, "Das eben erstellte Backup muss das jüngste sein"
    assert alte[-1] in ids and alte[-2] in ids, "Die jüngsten Alten bleiben trotz Überalterung"
    assert alte[0] not in ids, "Was weder jung noch geschützt ist, wird aufgeräumt"


async def test_aufraeumen_behaelt_die_juengsten_dateikopien_unabhaengig_vom_alter(welt, client, backup_verzeichnisse):
    """Dasselbe für die Dateikopien, die der Sync ausser Haus abholt."""
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    backup_verzeichnisse.mkdir(parents=True, exist_ok=True)
    vorzeiten = (datetime.now(timezone.utc) - timedelta(days=400)).timestamp()
    for jahr in (2020, 2021, 2022, 2023, 2024):
        pfad = backup_verzeichnisse / f"rbbk_ipad_verwaltung_backup_{jahr}-01-01_12-00-00.json.enc"
        pfad.write_bytes(b"alter Inhalt")
        os.utime(pfad, (vorzeiten, vorzeiten))

    antwort = await client.post("/api/backup/server-backups/run-now", headers=kopf)
    assert antwort.status_code == 200
    neue_datei = os.path.basename(antwort.json()["file_path"])

    verblieben = sorted(p.name for p in backup_verzeichnisse.glob("rbbk_ipad_verwaltung_backup_*"))
    assert len(verblieben) == SERVER_BACKUP_KEEP_MINIMUM
    assert neue_datei in verblieben
    assert "rbbk_ipad_verwaltung_backup_2024-01-01_12-00-00.json.enc" in verblieben
    assert "rbbk_ipad_verwaltung_backup_2020-01-01_12-00-00.json.enc" not in verblieben
