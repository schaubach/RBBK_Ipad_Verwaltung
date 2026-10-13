"""Datensicherung: Export, Wiederherstellung, Verschlüsselung und Aufräumen.

Ein Backup dieser Anwendung enthält den gesamten Schülerbestand samt der unterschriebenen
Leihverträge als PDF - also Namen, Adressen und Unterschriften von Schülern und Eltern.
Ein unverschlüsselt entstandenes Backup ist deshalb schlimmer als gar keines, und ein Backup,
das beim Zurückspielen die Zuständigkeiten verliert, ist keine Wiederherstellung.

Getestet wird über die HTTP-Endpunkte. Der Tagesjob hat keinen eigenen Endpunkt; wo er
gemeint ist, steht es im jeweiligen Docstring.
"""

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo.errors import DuplicateKeyError

from core.crypto import decrypt_backup_bytes, is_encrypted_backup, unwrap_secret
from routes.backup import (
    SERVER_BACKUP_KEEP_MINIMUM,
    SERVER_BACKUP_STATUS_UNVERAENDERT,
    _server_backup_due,
    ensure_itnr_index,
    run_scheduled_server_backup_check,
    save_server_backup,
)
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
    await db.students.insert_one(
        {
            "id": "s1",
            "name": "Mustermann",
            "vorname": "Erika",
            "bildungsgang_id": "bg_meda",
            "user_id": "u_schaubach",
        }
    )
    await db.ipads.insert_one(
        {
            "id": "i1",
            "itnr": "IT-1",
            "snr": "SN-1",
            "status": "ok",
            "bildungsgang_id": "bg_meda",
            "is_in_pool": False,
            "user_id": "u_schaubach",
        }
    )
    await db.assignments.insert_one(
        {
            "id": "a1",
            "student_id": "s1",
            "ipad_id": "i1",
            "itnr": "IT-1",
            "is_active": True,
            "bildungsgang_id": "bg_meda",
            "user_id": "u_schaubach",
            "assigned_at": datetime(2026, 2, 1, 8, 0, tzinfo=UTC),
        }
    )
    await db.contracts.insert_one(
        {
            "id": "v1",
            "assignment_id": "a1",
            "student_id": "s1",
            "ipad_id": "i1",
            "student_name": "Erika Mustermann",
            "filename": "vertrag_mustermann.pdf",
            "file_data": PDF_INHALT,
            "bildungsgang_id": "bg_meda",
            "user_id": "u_schaubach",
        }
    )


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
        f"rbbk_ipad_verwaltung_backup_alt-{tage:04d}.json.enc",
        b"alter Inhalt",
        metadata={"encrypted": True},
    )
    await db["backups.files"].update_one(
        {"_id": datei_id},
        {"$set": {"uploadDate": datetime.now(UTC) - timedelta(days=tage)}},
    )
    return str(datei_id)


def backup_datei(inhalt: dict) -> bytes:
    """Eine unverschlüsselte Backup-Datei, wie der Import sie weiterhin annimmt.

    Von Hand gebaut statt exportiert: die Prüfungen vor dem Einspielen gelten Dateien, die aus
    dem heutigen Export gar nicht herauskommen können - mit doppelter ITNr, mit Sammlungen aus
    der Zeit vor dem Umbau. Genau solche Dateien liegen im Archiv.
    """
    return json.dumps(inhalt, ensure_ascii=False).encode("utf-8")


def fremd_verpacktes_passwort(passwort: str) -> str:
    """Ein Backup-Passwort, verpackt mit dem SECRET_KEY eines ANDEREN Servers.

    So entsteht der Fall in der Anlage: Der Eintrag kommt aus einer älteren Sicherung oder von
    einem anderen Server, der SECRET_KEY zum Auspacken ist seitdem ein anderer. Es ist kein
    Datenmüll - mit dem passenden Schlüssel ließe er sich anstandslos öffnen.
    """
    fremder_schluessel = base64.urlsafe_b64encode(hashlib.sha256(b"SECRET_KEY des alten Servers").digest())
    return Fernet(fremder_schluessel).encrypt(passwort.encode("utf-8")).decode("ascii")


async def unlesbares_passwort_hinterlegen(db):
    """Ein Eintrag, der wie ein gesetztes Backup-Passwort aussieht, sich hier aber nicht mehr
    auspacken lässt."""
    await db.global_settings.insert_one(
        {
            "type": "backup_encryption",
            "wrapped_password": fremd_verpacktes_passwort("Backup-Passwort-123"),
        }
    )


def sicherheitsnetze() -> list:
    """Was tatsächlich im Verzeichnis der Sicherheitsnetze liegt - am Endpunkt vorbei.

    Der Endpunkt listet nur Dateien, die dem eigenen Namensmuster entsprechen; hier geht es
    darum, dass überhaupt nichts geschrieben wurde.
    """
    import routes.backup as backup

    verzeichnis = backup.PRE_RESTORE_BACKUPS_DIR
    return sorted(p.name for p in verzeichnis.glob("*")) if verzeichnis.exists() else []


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
    zustand = (await client.get("/api/settings/backup-encryption", headers=kopf)).json()
    assert zustand["password_configured"] is False
    assert zustand["password_state"] == "fehlt"


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
    assert (
        await welt.users.find_one({"id": "u_spaeter"}) is None
    ), "Wiederherstellung stellt den Stand des Backups her, sie ergänzt ihn nicht"
    assert (await client.get("/api/settings/backup-encryption", headers=kopf)).json()["password_configured"] is True


async def test_geraet_gehoert_nach_der_wiederherstellung_demselben_bildungsgang(welt, client):
    """Der Besitz hängt am Bildungsgang. Nach dem Zurückspielen muss schaubach genau sein
    MEDA-Gerät wiedersehen - und weiterhin nicht das des GYM.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    await welt.ipads.insert_one(
        {
            "id": "i_gym",
            "itnr": "IT-9",
            "snr": "SN-9",
            "status": "ok",
            "bildungsgang_id": "bg_gym",
            "is_in_pool": False,
            "user_id": "u_bakenecker",
        }
    )

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


# --- Das Backup-Passwort gehört dem Server, nicht der Datei -------------------------------


async def test_wiederherstellung_behaelt_das_eigene_backup_passwort(welt, client):
    """Der Fehler, der die Anlage im Oktober lahmgelegt hat.

    In der hochgespielten Datei steckt der backup_encryption-Eintrag von damals, verpackt mit
    dem SECRET_KEY von damals. Wurde er beim Einspielen zurückgeschrieben, stand danach ein
    Passwort da, das dieser Server nicht mehr öffnen konnte: Die Oberfläche meldete weiter
    "gesetzt", der Tagesjob scheiterte stündlich, und wochenlang entstand keine Sicherung.

    Der Eintrag sagt, womit DIESER Server verschlüsselt - er gehört zum Server und nicht zum
    Datenbestand der Schule. Alles andere aus global_settings gehört sehr wohl zurückgespielt;
    deshalb liegt in der Datei noch ein zweiter Eintrag, der danach dastehen muss.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    eigener_eintrag = await welt.global_settings.find_one({"type": "backup_encryption"})

    datei = backup_datei(
        {
            "bildungsgaenge": [],
            "students": [],
            "global_settings": [
                {"type": "backup_encryption", "wrapped_password": fremd_verpacktes_passwort("Passwort von damals")},
                {"type": "schuljahr", "wert": "2026/27"},
            ],
        }
    )
    antwort = await wiederherstellen(client, kopf, datei, dateiname="backup.json")
    assert antwort.status_code == 200, antwort.text

    eintraege = await welt.global_settings.find({"type": "backup_encryption"}).to_list(length=None)
    assert eintraege == [eigener_eintrag], "Der Eintrag des Servers steht unverändert da"
    assert (
        await welt.global_settings.find_one({"type": "schuljahr"}) is not None
    ), "Nur dieser eine Eintrag bleibt stehen - die Sammlung wird nicht weggeworfen"

    zustand = (await client.get("/api/settings/backup-encryption", headers=kopf)).json()
    assert zustand["password_state"] == "bereit", "Das Passwort lässt sich weiterhin entpacken"
    sicherung = (await client.get("/api/backup/export", headers=kopf)).content
    entpackt = decrypt_backup_bytes(sicherung, "Backup-Passwort-123")
    assert json.loads(entpackt.decode("utf-8"))[
        "global_settings"
    ], "Und der Backup-Lauf arbeitet weiter mit genau diesem Passwort"


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

    await welt.ipads.insert_one(
        {
            "id": "i2",
            "itnr": "IT-2",
            "snr": "SN-2",
            "status": "ok",
            "bildungsgang_id": "bg_it",
            "is_in_pool": False,
            "user_id": "u_schaubach",
        }
    )
    ergebnis = await save_server_backup(skip_if_unchanged=True)

    assert ergebnis["skipped"] is False
    assert len((await client.get("/api/backup/server-backups", headers=kopf)).json()) == 2


# --- Was der Tageslauf vermerkt -----------------------------------------------------------


async def faellig_machen(welt, tage=3) -> str:
    """Den Tageslauf fällig stellen und den Zeitpunkt zurückgeben, den er vorfindet.

    `run-now` vermerkt den Tag als erledigt; danach kehrt der stündliche Tick sofort wieder um.
    Hier werden beide Zeitpunkte so weit zurückdatiert, dass der Nachhol-Zweig greift - sonst
    hinge der Test an der Uhrzeit, zu der er läuft (SERVER_BACKUP_HOUR).

    Die Prüfsumme bleibt ausdrücklich stehen: nur so trifft der Lauf auf einen Bestand, den er
    als unverändert erkennt.
    """
    vorzeiten = (datetime.now(UTC) - timedelta(days=tage)).isoformat()
    await welt.global_settings.update_one(
        {"type": "server_backup_state"},
        {"$set": {"last_run_at": vorzeiten, "last_completed_at": vorzeiten}},
    )
    return vorzeiten


async def tageslauf_zustand(client, kopf) -> dict:
    antwort = await client.get("/api/backup/server-backups/status", headers=kopf)
    assert antwort.status_code == 200, antwort.text
    return antwort.json()


async def test_uebersprungener_tageslauf_laesst_last_run_at_stehen(welt, client):
    """Ein Lauf, der nichts geschrieben hat, darf nicht melden, heute sei gesichert worden.

    `last_run_at` ist die Angabe, aus der abgelesen wird, wie frisch die NEUESTE Sicherung ist.
    Rückte sie beim übersprungenen Lauf mit vor, meldete der Server in unveränderten Wochen
    (Ferien) täglich eine Sicherung von heute, während die jüngste in Wahrheit Wochen alt ist -
    und ein Schreiben, das längst nicht mehr funktioniert, fiele niemandem mehr auf.

    Der Tagesjob hat keinen eigenen Endpunkt; er wird hier direkt angestoßen. Nachgesehen wird
    aber dort, wo der Admin nachsieht: am Statusendpunkt und in der Liste.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200
    vorzeiten = await faellig_machen(welt)

    await run_scheduled_server_backup_check()

    danach = await tageslauf_zustand(client, kopf)
    assert danach["last_run_at"] == vorzeiten, "Die letzte GESCHRIEBENE Sicherung ist die von damals"
    assert (
        danach["last_status"] == SERVER_BACKUP_STATUS_UNVERAENDERT
    ), "'success' hieße: heute ist eine Sicherung entstanden"
    assert (
        len((await client.get("/api/backup/server-backups", headers=kopf)).json()) == 1
    ), "Und es ist auch wirklich keine entstanden"


async def test_uebersprungener_tageslauf_gilt_trotzdem_als_erledigt(welt, client):
    """Die andere Hälfte derselben Entscheidung: übersprungen heißt nicht offen.

    Der stündliche Tick fragt, ob der Tageslauf noch aussteht. Zählte dafür der Zeitpunkt der
    letzten geschriebenen Sicherung, baute der Job in unveränderten Wochen zu jedem Tick den
    gesamten Bestand neu zusammen und verschlüsselte ihn, nur um ihn wieder wegzuwerfen.
    Deshalb rückt `last_completed_at` auch beim übersprungenen Lauf vor.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200
    vorzeiten = await faellig_machen(welt)

    await run_scheduled_server_backup_check()

    gespeichert = await welt.global_settings.find_one({"type": "server_backup_state"})
    assert gespeichert["last_completed_at"] > vorzeiten, "Der Lauf ist durchgekommen, also ist der Tag erledigt"
    assert not _server_backup_due(gespeichert), "Der nächste stündliche Tick fängt nicht noch einmal an"


async def test_geschriebener_tageslauf_rueckt_last_run_at_vor(welt, client):
    """Die Gegenprobe: entsteht wirklich eine Sicherung, muss der Zeitpunkt mitgehen.

    Ohne sie bliebe ein `last_run_at`, das sich NIE mehr bewegt, unbemerkt - und die Meldung
    "die neueste Sicherung ist von damals" wäre genauso falsch wie die zu frische.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200
    vorzeiten = await faellig_machen(welt)
    await welt.ipads.insert_one(
        {
            "id": "i2",
            "itnr": "IT-2",
            "snr": "SN-2",
            "status": "ok",
            "bildungsgang_id": "bg_it",
            "is_in_pool": False,
            "user_id": "u_schaubach",
        }
    )

    await run_scheduled_server_backup_check()

    danach = await tageslauf_zustand(client, kopf)
    assert danach["last_run_at"] > vorzeiten
    assert danach["last_status"] == "success"
    assert len((await client.get("/api/backup/server-backups", headers=kopf)).json()) == 2


# --- Die Zeitangaben der Server-Backup-Liste ----------------------------------------------


async def test_die_zeitangaben_der_serverliste_tragen_eine_zeitzone(welt, client):
    """Jede Zeitangabe der Liste muss sagen, in welcher Zeitzone sie gilt.

    GridFS legt `uploadDate` als UTC OHNE Kennzeichen ab, und so kommt es auch aus dem Treiber
    zurück. Ohne Zeitzone liest der Browser die Angabe als Ortszeit - im Sommer zwei Stunden
    daneben. Geprüft werden beide Wege in die Liste: die eben erstellte Sicherung und eine, die
    schon länger in GridFS liegt.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    await altes_serverbackup(welt, tage=3)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    liste = (await client.get("/api/backup/server-backups", headers=kopf)).json()

    assert len(liste) == 2, liste
    for eintrag in liste:
        zeitpunkt = datetime.fromisoformat(eintrag["created_at"])
        assert zeitpunkt.utcoffset() is not None, f"{eintrag['filename']}: Zeitangabe ohne Zeitzone"


async def test_dieselbe_sicherung_steht_nicht_zweimal_verschoben_da(welt, client):
    """Der sichtbare Schaden, um den es ging.

    Die Oberfläche zeigt die Liste und den Status nebeneinander. `last_run_at` trug schon immer
    "+00:00", die Liste nicht - dieselbe Sicherung erschien dadurch an zwei Zeitpunkten, die um
    den Zeitzonenversatz auseinanderlagen. Verglichen wird deshalb nicht die Zeichenkette,
    sondern der Augenblick, den beide bezeichnen.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    liste = (await client.get("/api/backup/server-backups", headers=kopf)).json()
    gemeldet = datetime.fromisoformat((await tageslauf_zustand(client, kopf))["last_run_at"])

    assert len(liste) == 1, liste
    aus_der_liste = datetime.fromisoformat(liste[0]["created_at"])
    assert aus_der_liste.utcoffset() is not None, "Ohne Zeitzone ließe sich hier gar nicht vergleichen"
    assert abs(aus_der_liste - gemeldet) < timedelta(
        minutes=5
    ), "Liste und Status meinen dieselbe Sicherung - also denselben Augenblick"


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
    vorzeiten = (datetime.now(UTC) - timedelta(days=400)).timestamp()
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


# --- Ein Passwort, das keines mehr ist ----------------------------------------------------


async def test_unlesbares_backup_passwort_gilt_nicht_als_gesetzt(welt, client):
    """Der heimtückischste Zustand der ganzen Sicherung.

    In global_settings liegt ein Eintrag, mit dem aktuellen SECRET_KEY lässt er sich aber nicht
    mehr auspacken. Vorher genügte sein Vorhandensein für "Passwort gesetzt": die Oberfläche
    meldete grün, während jeder Backup-Lauf scheiterte. Wochenlang entstand nichts, und niemand
    hatte Anlass nachzusehen.
    """
    kopf = await anmelden(client, "admin")
    await unlesbares_passwort_hinterlegen(welt)
    await datenbestand(welt)

    zustand = (await client.get("/api/settings/backup-encryption", headers=kopf)).json()

    assert zustand["password_configured"] is False, "Ein Eintrag, den niemand öffnen kann, ist kein Passwort"
    assert zustand["password_state"] == "unlesbar"
    assert "nicht mehr entpacken" in zustand["message"]


async def test_unlesbares_backup_passwort_meldet_sich_beim_backup_lauf(welt, client):
    """Gegenprobe zur Statusmeldung: der Lauf scheitert wirklich - und sagt denselben Grund.

    Stünde hier "kein Backup-Passwort hinterlegt", setzte der Admin eines und fände es
    anschließend immer noch vor; die Meldung muss auf den Schlüssel zeigen.
    """
    kopf = await anmelden(client, "admin")
    await unlesbares_passwort_hinterlegen(welt)
    await datenbestand(welt)

    antwort = await client.post("/api/backup/server-backups/run-now", headers=kopf)

    assert antwort.status_code == 400
    assert "nicht mehr entpacken" in antwort.json()["detail"]
    assert (await client.get("/api/backup/server-backups", headers=kopf)).json() == []


@pytest.mark.parametrize(
    "gespeichert",
    [b"nicht als Text abgelegt", bytearray(b"nicht als Text abgelegt"), None, 12345],
    ids=["bytes", "bytearray", "nichts", "zahl"],
)
def test_ein_verpacktes_passwort_das_keine_zeichenkette_ist_gilt_als_unlesbar(gespeichert):
    """In global_settings kann etwas anderes liegen als eine Zeichenkette.

    bytes aus einem älteren Bestand, None aus einem halb geschriebenen Eintrag: Dann scheitert
    schon ``.encode`` mit einem AttributeError, und der Aufrufer bekäme einen Absturz zu sehen
    statt des Falles, den er ohnehin schon kennt und behandelt - nicht entpackbar.
    """
    assert unwrap_secret(gespeichert) is None


async def test_backup_passwort_als_bytes_meldet_unlesbar_statt_abzustuerzen(welt, client):
    """Derselbe Eintrag am Endpunkt: Der Admin soll lesen, was zu tun ist, und nicht einen
    Serverfehler bekommen.

    In der Datenbank landet so ein Wert als Binärfeld - und das ist genau der Zustand, in dem
    der Admin nachsieht, warum seit Tagen keine Sicherung mehr entsteht.
    """
    kopf = await anmelden(client, "admin")
    await welt.global_settings.insert_one(
        {
            "type": "backup_encryption",
            "wrapped_password": b"nicht als Text abgelegt",
        }
    )

    antwort = await client.get("/api/settings/backup-encryption", headers=kopf)

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["password_state"] == "unlesbar"
    assert antwort.json()["password_configured"] is False


async def test_wiederherstellung_ohne_passwort_legt_kein_klartext_netz_an(welt, client):
    """Das Sicherheitsnetz vor dem Einspielen ist ein vollständiges Abbild - mit Namen,
    Anschriften und unterschriebenen Verträgen.

    Ohne Passwort landete es als reines JSON im Upload-Verzeichnis. Der Export verweigert aus
    genau diesem Grund jede unverschlüsselte Sicherung; auf diesem Weg darf nicht entstehen,
    was auf dem anderen verboten ist.
    """
    kopf = await anmelden(client, "admin")
    await datenbestand(welt)

    antwort = await wiederherstellen(client, kopf, backup_datei({"students": []}), dateiname="backup.json")

    assert antwort.status_code == 400
    assert "Backup-Passwort" in antwort.json()["detail"]
    assert sicherheitsnetze() == [], "Ohne Passwort darf gar kein Abbild entstehen"
    assert await welt.students.count_documents({}) == 1, "Ein abgelehnter Import darf nichts anfassen"


async def test_wiederherstellung_mit_unlesbarem_passwort_legt_kein_klartext_netz_an(welt, client):
    """Derselbe Riegel für den Eintrag, der sich nicht mehr öffnen lässt: hinterlegt ist er,
    verschlüsseln kann man damit trotzdem nichts."""
    kopf = await anmelden(client, "admin")
    await unlesbares_passwort_hinterlegen(welt)
    await datenbestand(welt)

    antwort = await wiederherstellen(client, kopf, backup_datei({"students": []}), dateiname="backup.json")

    assert antwort.status_code == 400
    assert "nicht mehr entpacken" in antwort.json()["detail"]
    assert sicherheitsnetze() == []
    assert await welt.students.count_documents({}) == 1


# --- Was die hochgeladene Datei mitbringt -------------------------------------------------


async def test_doppelte_itnr_in_der_datei_wird_mit_nummer_abgelehnt(welt, client):
    """Eine ITNr bezeichnet genau ein Gerät - zweimal dieselbe ist keine Sicherung.

    Ohne Vorabprüfung bräche insert_many mitten im Schreiben ab: der Schülerbestand wäre dann
    schon ersetzt, die Geräte halb, und der Admin bekäme den rohen Mongo-Text zu lesen. Die
    Meldung muss die Nummer nennen, sonst ist die Datei nicht zu bereinigen.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    datei = backup_datei(
        {
            "students": [],
            "ipads": [
                {"id": "i7", "itnr": "IT-7", "snr": "SN-7", "status": "ok", "bildungsgang_id": "bg_meda"},
                {"id": "i8", "itnr": "IT-7", "snr": "SN-8", "status": "ok", "bildungsgang_id": "bg_meda"},
            ],
        }
    )
    antwort = await wiederherstellen(client, kopf, datei, dateiname="backup.json")

    assert antwort.status_code == 400
    assert "IT-7" in antwort.json()["detail"], "Ohne die Nummer weiß niemand, wo er suchen soll"
    assert "ITNr" in antwort.json()["detail"]
    assert await welt.students.count_documents({}) == 1, "Kein halb geschriebener Bestand"
    assert [g["itnr"] for g in await welt.ipads.find({}).to_list(length=None)] == ["IT-1"]
    assert sicherheitsnetze() == [], "Was gar nicht erst eingespielt wird, braucht kein Netz"


@pytest.mark.parametrize(
    "itnr_felder,erwartet",
    [
        ({}, "ohne ITNr"),
        ({"itnr": ""}, "leere ITNr"),
        ({"itnr": "   "}, "leere ITNr"),
        ({"itnr": 7}, "7 (als Zahl, nicht als Text)"),
    ],
    ids=["fehlt", "leer", "nur-leerzeichen", "zahl"],
)
async def test_doppelte_itnr_wird_auch_ohne_richtige_nummer_erkannt(welt, client, itnr_felder, erwartet):
    """Dublette ist nicht nur, was zweimal dieselbe Nummer trägt.

    Für den eindeutigen Index auf ipads.itnr sind zwei fehlende Felder dieselbe Nummer, zwei
    leere Felder auch, und eine Zahl ist ein Schlüssel wie jeder andere. Die Vorabprüfung
    übersprang früher alles, was keine nichtleere Zeichenkette war: Solche Dateien kamen durch
    und liefen erst beim Schreiben in den Index - der Bestand war dann schon halb ersetzt und
    der Admin las rohen Mongo-Text.

    Je Fall einzeln, denn jeder entsteht anders: ein Export von vor der ITNr-Pflicht, eine
    Tabellenkalkulation mit leeren Zellen, eine, die "0815" als Zahl gespeichert hat.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    datei = backup_datei(
        {
            "students": [],
            "ipads": [
                {"id": "i7", "snr": "SN-7", "status": "ok", "bildungsgang_id": "bg_meda", **itnr_felder},
                {"id": "i8", "snr": "SN-8", "status": "ok", "bildungsgang_id": "bg_meda", **itnr_felder},
            ],
        }
    )
    antwort = await wiederherstellen(client, kopf, datei, dateiname="backup.json")

    assert antwort.status_code == 400, antwort.text
    assert erwartet in antwort.json()["detail"], "Die Meldung muss sagen, welcher Eintrag gemeint ist"
    assert await welt.students.count_documents({}) == 1, "Kein halb geschriebener Bestand"
    assert [g["itnr"] for g in await welt.ipads.find({}).to_list(length=None)] == ["IT-1"]
    assert sicherheitsnetze() == [], "Was gar nicht erst eingespielt wird, braucht kein Netz"


async def test_zahl_und_zeichenkette_sind_keine_dublette(welt, client):
    """Gegenprobe: 7 und "7" sind für die Datenbank zwei verschiedene Nummern.

    Wer beim Vergleichen alles in Text verwandelt, lehnt eine Datei ab, die sich einwandfrei
    einspielen lässt - und im Notfall steht die Schule dann vor einer Sicherung, die niemand
    mehr zurückbekommt. Dass der eindeutige Index danach steht, ist der Beweis: Die Datenbank
    sieht hier wirklich zwei Schlüssel.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    datei = backup_datei(
        {
            "students": [],
            "ipads": [
                {"id": "i7", "itnr": 7, "snr": "SN-7", "status": "ok", "bildungsgang_id": "bg_meda"},
                {"id": "i8", "itnr": "7", "snr": "SN-8", "status": "ok", "bildungsgang_id": "bg_meda"},
            ],
        }
    )
    antwort = await wiederherstellen(client, kopf, datei, dateiname="backup.json")

    assert antwort.status_code == 200, antwort.text
    assert antwort.json()["itnr_index_ok"] is True, "Die Datenbank selbst nimmt beide an"
    assert await welt.ipads.count_documents({}) == 2


async def test_datei_von_vor_dem_umbau_wird_als_solche_gemeldet(welt, client):
    """Eine Sicherung aus der Zeit der "departments" lässt sich einspielen - nur gehört danach
    nichts mehr zu einem Bildungsgang.

    Abgelehnt wird sie trotzdem nicht: im Notfall ist gerade die alte Datei die, nach der
    gegriffen wird. Die Antwort muss aber sagen, was man vor sich hat, und den Weg nennen -
    sonst sitzt die Schule vor einer Verwaltung, in der niemand außer dem Admin etwas sieht,
    und hält es für einen Rechtefehler.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)

    datei = backup_datei(
        {
            "departments": [{"id": "d_meda", "name": "MEDA", "user_id": "u_schaubach"}],
            "students": [{"id": "s_alt", "sus_vorn": "Alt", "sus_nachn": "Bestand", "user_id": "u_schaubach"}],
            "ipads": [{"id": "i_alt", "itnr": "IT-ALT", "snr": "SN-ALT", "status": "ok", "user_id": "u_schaubach"}],
        }
    )
    antwort = await wiederherstellen(client, kopf, datei, dateiname="backup.json")

    assert antwort.status_code == 200, antwort.text
    befund = antwort.json()
    assert befund["vor_dem_umbau"] is True
    assert "migrate-to-bildungsgang.py" in befund["message"], "Die Meldung muss den Weg nennen"
    assert any("Bildungsgänge" in warnung for warnung in befund["warnungen"])
    assert befund["ohne_bildungsgang"] == {"students": 1, "ipads": 1}
    assert "bildungsgaenge" in befund["fehlende_sammlungen"]

    lehrkraft = await anmelden(client, "schaubach")
    assert (
        await client.get("/api/ipads", headers=lehrkraft)
    ).json() == [], "Das ist die Folge, vor der die Warnung steht"


def test_pool_ipads_gelten_beim_einspielen_nicht_als_herrenlos():
    """Ein Pool-iPad hat absichtlich keinen Bildungsgang - das ist kein Befund.

    Früher zählte jedes iPad ohne bildungsgang_id als herrenlos. Jede Anlage mit Pool-Geräten
    bekam deshalb bei jeder Wiederherstellung "ACHTUNG: Ohne Bildungsgang kommen an", und eine
    Warnung, die immer kommt, liest irgendwann niemand mehr - auch dann nicht, wenn sie stimmt.
    """
    from routes.backup import pruefe_backup_inhalt

    befund = pruefe_backup_inhalt(
        {
            "bildungsgaenge": [{"id": "bg_meda", "name": "MEDA"}],
            "ipads": [
                {"id": "i_pool", "itnr": "IT-POOL", "is_in_pool": True, "bildungsgang_id": None},
                {"id": "i_los", "itnr": "IT-LOS", "is_in_pool": False, "bildungsgang_id": None},
                {"id": "i_meda", "itnr": "IT-MEDA", "is_in_pool": False, "bildungsgang_id": "bg_meda"},
            ],
        }
    )

    assert befund["ohne_bildungsgang"] == {"ipads": 1}, "Nur das wirklich herrenlose Gerät zählt"
    assert any("Ohne Bildungsgang kommen an: 1 " in w for w in befund["warnungen"])

    nur_pool = pruefe_backup_inhalt(
        {"bildungsgaenge": [], "ipads": [{"id": "i_pool", "itnr": "IT-POOL", "is_in_pool": True}]}
    )
    assert nur_pool["ohne_bildungsgang"] == {}
    assert not any("Ohne Bildungsgang" in w for w in nur_pool["warnungen"])


# --- Der eindeutige Index auf ipads.itnr --------------------------------------------------


async def test_ensure_itnr_index_legt_den_index_wirklich_an(db):
    """Nachgesehen wird in der Datenbank, nicht im Rückgabewert.

    Die Funktion berichtet über sich selbst; ob der Index danach wirklich steht, sagt allein
    die Datenbank. Und "steht" heißt eindeutig: ohne die Eindeutigkeit nimmt sie zwei Geräte
    mit derselben ITNr klaglos auf - genau darauf verlässt sich der Batch-Upload, dessen
    atomares ``$setOnInsert`` das Wettrennen zweier gleichzeitiger Läufe nur schließt, wenn
    die zweite Einfügung an diesem Index scheitert.
    """
    await db.ipads.insert_one(
        {
            "id": "i1",
            "itnr": "IT-1",
            "snr": "SN-1",
            "status": "ok",
            "bildungsgang_id": "bg_meda",
        }
    )
    assert "itnr_eindeutig" not in await db.ipads.index_information()

    ergebnis = await ensure_itnr_index()

    assert ergebnis["ok"] is True
    index = (await db.ipads.index_information())["itnr_eindeutig"]
    assert index["key"] == [("itnr", 1)]
    assert index.get("unique") is True
    with pytest.raises(DuplicateKeyError):
        await db.ipads.insert_one(
            {
                "id": "i2",
                "itnr": "IT-1",
                "snr": "SN-2",
                "status": "ok",
                "bildungsgang_id": "bg_meda",
            }
        )


async def test_ensure_itnr_index_entsteht_bei_dubletten_nicht_und_nennt_die_zahl(db):
    """Gegenprobe: Steht dieselbe ITNr schon zweimal im Bestand, lässt die Datenbank den Index
    nicht zu.

    Die Anwendung läuft trotzdem weiter - ein Deploy auf eine unsaubere Datenbank darf nicht
    die ganze Verwaltung stillstellen. Die Meldung muss dann aber die ANZAHL nennen: "bitte
    bereinigen" ohne Zahl lässt denjenigen, der es liest, ratlos zurück.
    """
    await db.ipads.insert_many(
        [
            {"id": "i1", "itnr": "IT-1", "snr": "SN-1", "status": "ok", "bildungsgang_id": "bg_meda"},
            {"id": "i2", "itnr": "IT-1", "snr": "SN-2", "status": "ok", "bildungsgang_id": "bg_meda"},
            {"id": "i3", "itnr": "IT-3", "snr": "SN-3", "status": "ok", "bildungsgang_id": "bg_meda"},
        ]
    )

    ergebnis = await ensure_itnr_index()

    assert ergebnis["ok"] is False
    assert ergebnis["duplikate"] == 1
    assert "1 ITNr kommt mehrfach vor" in ergebnis["meldung"]
    assert (
        "itnr_eindeutig" not in await db.ipads.index_information()
    ), "Was die Datenbank ablehnt, darf hinterher nicht doch dastehen"


async def test_fehlender_index_ohne_dubletten_behauptet_keine(welt, client):
    """Fehlt der Index, ohne dass es Dubletten gibt, darf die Meldung keine behaupten.

    Vorher stand in jeder Meldung, es gebe welche - auch bei null gezählten. Das schickt
    denjenigen, der sie liest, auf die Suche nach etwas, das es nicht gibt, und die eigentliche
    Spur (das Server-Protokoll vom letzten Start) sucht er dann gar nicht erst.
    """
    kopf = await anmelden(client, "admin")
    await datenbestand(welt)

    status = (await client.get("/api/backup/server-backups/status", headers=kopf)).json()

    assert status["itnr_index_ok"] is False
    assert status["itnr_duplikate"] == 0
    assert "doppelte ITNr gibt es aber keine" in status["itnr_index_meldung"]
    assert "Server-Protokoll" in status["itnr_index_meldung"], "Die Meldung muss woandershin zeigen"


async def test_fehlender_index_mit_dubletten_nennt_die_zahl(welt, client):
    """Gibt es Dubletten, steht ihre ANZAHL in der Meldung.

    "Bitte bereinigen" ohne Zahl lässt denjenigen, der es liest, ratlos zurück: Er weiß nicht,
    ob er eine Nummer sucht oder hundert.
    """
    kopf = await anmelden(client, "admin")
    await welt.ipads.insert_many(
        [
            {"id": "i1", "itnr": "IT-1", "snr": "SN-1", "status": "ok", "bildungsgang_id": "bg_meda"},
            {"id": "i2", "itnr": "IT-1", "snr": "SN-2", "status": "ok", "bildungsgang_id": "bg_meda"},
        ]
    )

    status = (await client.get("/api/backup/server-backups/status", headers=kopf)).json()

    assert status["itnr_index_ok"] is False
    assert status["itnr_duplikate"] == 1
    assert "1 ITNr kommt mehrfach vor" in status["itnr_index_meldung"]


# --- Ein neues Backup-Passwort und das, was es kostet --------------------------------------


async def test_neues_backup_passwort_nennt_die_zahl_der_unlesbaren_sicherungen(welt, client):
    """Ein Passwortwechsel macht jede vorhandene Sicherung dauerhaft unlesbar.

    Nachträglich umschlüsseln kann das niemand: Jede Datei hängt an dem Passwort, mit dem sie
    entstanden ist. "Backup-Passwort erfolgreich gesetzt" allein verschweigt genau das - und
    wer es liest, wirft das alte Passwort weg und damit sein ganzes Archiv. Die Zahl muss
    dabeistehen, sonst ahnt niemand, wie viel daran hängt.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf, "Erstes-Passwort-123")
    await datenbestand(welt)
    for _ in range(2):
        assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    antwort = await client.put(
        "/api/settings/backup-encryption", json={"password": "Zweites-Passwort-123"}, headers=kopf
    )

    assert antwort.status_code == 200, antwort.text
    befund = antwort.json()
    assert befund["sicherungen_gesamt"] == 2
    assert befund["sicherungen_unlesbar"] == 2
    assert "2 vorhandene Sicherungen lassen sich" in befund["message"]
    assert "ACHTUNG" in befund["message"]


async def test_dasselbe_backup_passwort_erneut_gesetzt_warnt_nicht(welt, client):
    """Der Weg, mit dem der Backup-Lauf repariert wird: dasselbe Passwort noch einmal setzen.

    Der hinterlegte Eintrag lässt sich nicht mehr entpacken (anderer SECRET_KEY), das Archiv ist
    aber mit genau diesem Passwort verschlüsselt und bleibt es auch. Käme hier die Warnung, die
    Sicherungen seien jetzt unlesbar, wäre sie falsch - und sie schreckte genau denjenigen ab,
    der die Reparatur gerade vornimmt. Prüfen lässt sich das nur am Archiv selbst: Der Eintrag
    taugt in diesem Fall nicht zum Vergleich, er ist ja nicht mehr zu öffnen.
    """
    kopf = await anmelden(client, "admin")
    await passwort_setzen(client, kopf)
    await datenbestand(welt)
    assert (await client.post("/api/backup/server-backups/run-now", headers=kopf)).status_code == 200

    # Derselbe Eintrag, nur mit einem fremden Schlüssel verpackt - der Zustand in der Anlage.
    await welt.global_settings.delete_many({"type": "backup_encryption"})
    await unlesbares_passwort_hinterlegen(welt)
    assert (await client.get("/api/settings/backup-encryption", headers=kopf)).json()["password_state"] == "unlesbar"

    antwort = await client.put(
        "/api/settings/backup-encryption", json={"password": "Backup-Passwort-123"}, headers=kopf
    )

    assert antwort.status_code == 200, antwort.text
    befund = antwort.json()
    assert befund["sicherungen_unlesbar"] == 0, "Dasselbe Passwort kostet das Archiv nichts"
    assert "ACHTUNG" not in befund["message"], "Eine falsche Warnung hält von der Reparatur ab"
    assert "1 vorhandene Sicherung lässt sich" in befund["message"]
    zustand = (await client.get("/api/settings/backup-encryption", headers=kopf)).json()
    assert zustand["password_state"] == "bereit", "Und der Backup-Lauf ist damit repariert"
