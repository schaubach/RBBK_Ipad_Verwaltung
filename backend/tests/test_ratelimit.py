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
