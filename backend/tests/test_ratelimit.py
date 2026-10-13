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


def test_nur_ein_ausdrueckliches_true_schaltet_die_bremse_ab():
    """DISABLE_RATE_LIMIT=true gibt es nur für den Browser-Test-Stack (e2e/docker-compose.yml).

    Eine echte Installation setzt die Variable nicht - dann muss die Bremse an sein. Ein
    Fehler in der Auswertung, der sie still abschaltet, fiele sonst niemandem auf.
    """
    from core.config import RATE_LIMIT_DISABLED, rate_limit_disabled

    assert RATE_LIMIT_DISABLED is False  # die Testumgebung setzt die Variable nicht
    assert rate_limit_disabled(None) is False
    assert rate_limit_disabled("") is False
    assert rate_limit_disabled("false") is False
    assert rate_limit_disabled("1") is False  # nur "true" zählt, nichts Erratenes
    assert rate_limit_disabled("true") is True
    assert rate_limit_disabled(" TRUE ") is True


def test_slowapi_liest_den_eigenen_schalter_nicht_um(monkeypatch):
    """slowapi wertet RATELIMIT_ENABLED selbst aus, und zwar als Text - "false" gälte als an.

    Deshalb heißt unser Schalter anders. Dieser Test hält fest, warum: Würde jemand ihn auf
    RATELIMIT_ENABLED umbenennen, ließe sich die Bremse damit gar nicht mehr abschalten.
    """
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    monkeypatch.setenv("RATELIMIT_ENABLED", "false")
    assert Limiter(key_func=get_remote_address, enabled=False).enabled == "false"
