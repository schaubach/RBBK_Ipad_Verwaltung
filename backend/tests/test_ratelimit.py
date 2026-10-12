"""Die Mengenbegrenzung - hier ausdrücklich eingeschaltet.

Sie ist der Schutz gegen das Durchprobieren von Passwörtern und gegen massenhaftes
Abziehen von Daten. conftest schaltet sie für alle anderen Tests ab; hier wird sie
gezielt geprüft, sonst würde niemand bemerken, wenn sie wegfiele.
"""

import pytest


@pytest.fixture
def mit_ratelimit():
    from core.config import limiter

    limiter.enabled = True
    limiter.reset()
    yield
    limiter.enabled = False


async def test_anmeldung_wird_nach_fuenf_versuchen_gebremst(welt, client, mit_ratelimit):
    falsch = {"username": "schaubach", "password": "falsch"}
    codes = [(await client.post("/api/auth/login", json=falsch)).status_code for _ in range(7)]
    assert 429 in codes, f"Keine Bremse ausgelöst: {codes}"
    assert codes.index(429) <= 5, f"Bremse griff zu spät: {codes}"


def test_nur_ein_ausdrueckliches_false_schaltet_die_bremse_ab():
    """RATELIMIT_ENABLED=false gibt es nur für den Browser-Test-Stack (e2e/docker-compose.yml).

    Eine echte Installation setzt die Variable nicht - dann muss die Bremse an sein. Ein
    Fehler in der Auswertung, der sie still abschaltet, fiele sonst niemandem auf.
    """
    from core.config import RATELIMIT_ENABLED, ratelimit_enabled

    assert RATELIMIT_ENABLED is True  # die Testumgebung setzt die Variable nicht
    assert ratelimit_enabled(None) is True
    assert ratelimit_enabled("") is True
    assert ratelimit_enabled("true") is True
    assert ratelimit_enabled("0") is True  # nur "false" zählt, nichts Erratenes
    assert ratelimit_enabled("false") is False
    assert ratelimit_enabled(" FALSE ") is False
