
from protocol import (
    simulate_unauthenticated_mitm,
    simulate_authenticated_exchange,
    simulate_authenticated_mitm_attempt,
)


def test_unauthenticated_mitm():
    result = simulate_unauthenticated_mitm()

    assert result["attack_succeeded"] is True
    assert result["alice_mallory_secret_match"] is True
    assert result["bob_mallory_secret_match"] is True
    assert result["alice_bob_secret_match"] is False
    assert result["eavesdropping_successful"] is True
    assert result["relay_successful"] is True

    print("Unauthenticated MITM attack: PASS")


def test_authenticated_exchange():
    result = simulate_authenticated_exchange()

    assert result["authentication_successful"] is True
    assert result["shared_secrets_match"] is True
    assert result["message_decryption_successful"] is True
    assert result["exchange_successful"] is True

    print("Authenticated exchange: PASS")


def test_authenticated_mitm_blocked():
    result = simulate_authenticated_mitm_attempt()

    assert result["authentication_successful"] is False
    assert result["mitm_attack_blocked"] is True
    assert result["exchange_successful"] is False

    print("Authenticated MITM rejection: PASS")


if __name__ == "__main__":
    test_unauthenticated_mitm()
    test_authenticated_exchange()
    test_authenticated_mitm_blocked()
    print("All protocol tests passed.")
