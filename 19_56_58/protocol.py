"""Protocol simulation module.

Demonstrates unauthenticated Diffie-Hellman key exchange (vulnerable to MITM)
and authenticated Diffie-Hellman key exchange using Ed25519 digital signatures
binding sender, recipient, and protocol context.
"""

from typing import Any
from cryptography.exceptions import InvalidSignature, InvalidTag

from key_exchange import derive_shared_secret, generate_key_pair, verify_shared_secret
from key_derivation import derive_key
from encryption import decrypt_message, encrypt_message
from authentication import (
    generate_signing_key_pair,
    sign_public_key,
    verify_public_key_signature,
)


def simulate_unauthenticated_mitm(
    message: bytes = b"Meet me at the station at noon.",
) -> dict[str, Any]:
    """Simulate an active Man-in-the-Middle (MITM) attack on unauthenticated X25519.

    In an unauthenticated Diffie-Hellman exchange, public keys are transmitted
    without digital signatures or identity binding. An active adversary (Mallory)
    can intercept and replace public keys in transit, establishing two independent
    shared secrets (one with Alice, one with Bob) and completely compromising
    confidentiality and integrity.

    Args:
        message: The plaintext demonstration message Alice sends to Bob.

    Returns:
        dict[str, Any]: Structured summary indicating the outcome of the attack,
        including key match statuses and message delivery verification.

    Raises:
        TypeError: If message is not a bytes-like object.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be a bytes-like object")

    # Step 1: Alice and Bob generate their genuine X25519 key pairs.
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # Step 2: Mallory (the MITM attacker) generates her own separate X25519 key pairs
    # to masquerade as Bob toward Alice, and as Alice toward Bob.
    mallory_alice_private, mallory_alice_public = generate_key_pair()
    mallory_bob_private, mallory_bob_public = generate_key_pair()

    # Step 3: Key interception and substitution.
    # - Alice sends alice_public, but Mallory intercepts it and sends mallory_bob_public to Bob.
    # - Bob sends bob_public, but Mallory intercepts it and sends mallory_alice_public to Alice.
    alice_received_public = mallory_alice_public
    bob_received_public = mallory_bob_public

    # Step 4: Shared secret derivation.
    alice_shared_secret = derive_shared_secret(alice_private, alice_received_public)
    mallory_shared_secret_alice = derive_shared_secret(mallory_alice_private, alice_public)

    bob_shared_secret = derive_shared_secret(bob_private, bob_received_public)
    mallory_shared_secret_bob = derive_shared_secret(mallory_bob_private, bob_public)

    # Step 5: Derive symmetric AES-256 keys via HKDF.
    alice_key = derive_key(alice_shared_secret)
    mallory_alice_key = derive_key(mallory_shared_secret_alice)

    bob_key = derive_key(bob_shared_secret)
    mallory_bob_key = derive_key(mallory_shared_secret_bob)

    # Verify secret agreement properties
    alice_mallory_match = verify_shared_secret(alice_shared_secret, mallory_shared_secret_alice)
    bob_mallory_match = verify_shared_secret(bob_shared_secret, mallory_shared_secret_bob)
    alice_bob_match = verify_shared_secret(alice_shared_secret, bob_shared_secret)

    # Step 6: Message transmission, interception, decryption, and relay.
    # Alice encrypts message for Bob using her derived key (which is actually shared with Mallory).
    alice_nonce, alice_ciphertext = encrypt_message(alice_key, bytes(message))

    mallory_decrypted: bytes | None = None
    bob_decrypted: bytes | None = None
    attack_succeeded = False

    try:
        # Mallory intercepts Alice's ciphertext and decrypts it with mallory_alice_key.
        mallory_decrypted = decrypt_message(mallory_alice_key, alice_nonce, alice_ciphertext)

        # Mallory re-encrypts the intercepted message for Bob using mallory_bob_key.
        mallory_nonce, mallory_ciphertext = encrypt_message(mallory_bob_key, mallory_decrypted)

        # Bob receives the ciphertext from Mallory (believing it came from Alice) and decrypts it.
        bob_decrypted = decrypt_message(bob_key, mallory_nonce, mallory_ciphertext)

        # The attack succeeds if Mallory successfully intercepted and read Alice's plaintext,
        # relayed it to Bob, while Alice and Bob never actually shared the same secret.
        attack_succeeded = (
            alice_mallory_match
            and bob_mallory_match
            and not alice_bob_match
            and mallory_decrypted == message
            and bob_decrypted == message
        )
    except (InvalidTag, ValueError, TypeError):
        attack_succeeded = False

    return {
        "attack_succeeded": attack_succeeded,
        "alice_mallory_secret_match": alice_mallory_match,
        "bob_mallory_secret_match": bob_mallory_match,
        "alice_bob_secret_match": alice_bob_match,
        "original_message": bytes(message),
        "mallory_intercepted_message": mallory_decrypted,
        "bob_received_message": bob_decrypted,
        "eavesdropping_successful": mallory_decrypted == message,
        "relay_successful": bob_decrypted == message,
    }


def simulate_authenticated_exchange(
    message: bytes = b"Authenticated message from Alice to Bob.",
) -> dict[str, Any]:
    """Simulate a secure, authenticated Diffie-Hellman key exchange.

    Alice and Bob possess pre-established, trusted Ed25519 public keys. During the
    ephemeral X25519 key exchange, each party signs their ephemeral public key
    bound explicitly to their identity, the intended peer identity, and protocol ID.
    Each party verifies the signature against the peer's pre-shared trusted signing
    key and expected context before deriving shared secrets or session keys.

    Args:
        message: The plaintext demonstration message to encrypt and transmit.

    Returns:
        dict[str, Any]: Non-secret status information about the authenticated exchange.

    Raises:
        TypeError: If message is not a bytes-like object.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be a bytes-like object")

    # Step 1: Pre-provisioned long-term identity signing keys (trusted out-of-band).
    alice_signing_private, alice_signing_public = generate_signing_key_pair()
    bob_signing_private, bob_signing_public = generate_signing_key_pair()

    trusted_alice_signing_public = alice_signing_public
    trusted_bob_signing_public = bob_signing_public

    # Step 2: Generate ephemeral X25519 exchange key pairs.
    alice_exchange_private, alice_exchange_public = generate_key_pair()
    bob_exchange_private, bob_exchange_public = generate_key_pair()

    # Step 3: Sign ephemeral public keys, binding sender, recipient, and protocol ID.
    alice_signature = sign_public_key(
        alice_signing_private,
        alice_exchange_public,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )
    bob_signature = sign_public_key(
        bob_signing_private,
        bob_exchange_public,
        sender_id=b"Bob",
        recipient_id=b"Alice",
    )

    # Step 4: Verify peer signatures against expected sender, recipient, and protocol.
    alice_verified_bob = verify_public_key_signature(
        trusted_bob_signing_public,
        bob_exchange_public,
        bob_signature,
        sender_id=b"Bob",
        recipient_id=b"Alice",
    )
    bob_verified_alice = verify_public_key_signature(
        trusted_alice_signing_public,
        alice_exchange_public,
        alice_signature,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )

    authentication_successful = alice_verified_bob and bob_verified_alice

    shared_secrets_match = False
    message_decryption_successful = False
    exchange_successful = False

    # Step 5: Only proceed if authentication succeeds.
    if authentication_successful:
        # Derive shared secrets
        alice_shared_secret = derive_shared_secret(
            alice_exchange_private, bob_exchange_public
        )
        bob_shared_secret = derive_shared_secret(
            bob_exchange_private, alice_exchange_public
        )

        shared_secrets_match = verify_shared_secret(
            alice_shared_secret, bob_shared_secret
        )

        # Derive symmetric encryption keys via HKDF
        alice_key = derive_key(alice_shared_secret)
        bob_key = derive_key(bob_shared_secret)

        # Encrypt demonstration message from Alice to Bob
        nonce, ciphertext = encrypt_message(alice_key, bytes(message))

        # Bob decrypts the message
        try:
            bob_decrypted = decrypt_message(bob_key, nonce, ciphertext)
            message_decryption_successful = bob_decrypted == message
        except InvalidTag:
            message_decryption_successful = False

        exchange_successful = (
            authentication_successful
            and shared_secrets_match
            and message_decryption_successful
        )

    return {
        "authentication_successful": authentication_successful,
        "shared_secrets_match": shared_secrets_match,
        "message_decryption_successful": message_decryption_successful,
        "exchange_successful": exchange_successful,
    }


def simulate_authenticated_mitm_attempt() -> dict[str, Any]:
    """Simulate a thwarted MITM attack against authenticated Diffie-Hellman.

    Mallory intercepts Alice's key exchange message to Bob and substitutes her own
    ephemeral X25519 public key. Because Mallory lacks Alice's trusted Ed25519
    signing key, Mallory cannot forge a valid signature binding Mallory's public key
    to Alice's sender identity and Bob's recipient identity. Bob verifies the
    incoming key against Alice's trusted public key, detects the failure,
    raises/catches InvalidSignature, and aborts before deriving keys.

    Returns:
        dict[str, Any]: Non-secret status information showing the attack was rejected.
    """
    # Step 1: Pre-provisioned long-term identity keys (trusted out-of-band).
    alice_signing_private, alice_signing_public = generate_signing_key_pair()
    bob_signing_private, bob_signing_public = generate_signing_key_pair()

    trusted_alice_signing_public = alice_signing_public

    # Step 2: Alice generates and signs her legitimate ephemeral X25519 public key
    # explicitly bound to sender Alice and recipient Bob.
    alice_exchange_private, alice_exchange_public = generate_key_pair()
    alice_signature = sign_public_key(
        alice_signing_private,
        alice_exchange_public,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )

    # Step 3: Mallory intercepts Alice's transmission and attempts substitution.
    mallory_exchange_private, mallory_exchange_public = generate_key_pair()

    # Mallory forwards her substituted X25519 key to Bob purporting to be Alice.
    authentication_successful = False
    mitm_attack_blocked = False

    # Step 4: Bob verifies the incoming public key using Alice's trusted Ed25519 key
    # expecting sender_id=b"Alice" and recipient_id=b"Bob".
    try:
        is_valid = verify_public_key_signature(
            trusted_alice_signing_public,
            mallory_exchange_public,
            alice_signature,
            sender_id=b"Alice",
            recipient_id=b"Bob",
        )
        if not is_valid:
            raise InvalidSignature(
                "Signature verification failed: substituted key does not match signature"
            )
        authentication_successful = True
    except InvalidSignature:
        authentication_successful = False
        mitm_attack_blocked = True

    # Step 5: If authentication fails, abort. Do NOT derive shared secrets or session keys.
    return {
        "authentication_successful": authentication_successful,
        "mitm_attack_blocked": mitm_attack_blocked,
        "shared_secrets_match": False,
        "message_decryption_successful": False,
        "exchange_successful": False,
    }
