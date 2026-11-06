from key_exchange import generate_key_pair
from authentication import (
    generate_signing_key_pair,
    sign_public_key,
    verify_public_key_signature,
)


def test_authentication():
    # Alice generates her X25519 key pair and Ed25519 signing key pair.
    alice_exchange_private, alice_exchange_public = generate_key_pair()
    alice_signing_private, alice_signing_public = generate_signing_key_pair()

    # Alice signs her X25519 public key bound to sender Alice and recipient Bob.
    alice_signature = sign_public_key(
        alice_signing_private,
        alice_exchange_public,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )

    # Test 1: Verify Alice's genuine signature with correct sender and recipient.
    valid = verify_public_key_signature(
        alice_signing_public,
        alice_exchange_public,
        alice_signature,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )
    print("Genuine signature accepted:", valid)

    # Mallory generates her own signing and exchange key pairs.
    mallory_signing_private, mallory_signing_public = (
        generate_signing_key_pair()
    )
    mallory_exchange_private, mallory_exchange_public = (
        generate_key_pair()
    )

    # Test 2: Mallory signs her key, but Alice's trusted public key
    # is used for verification.
    mallory_signature = sign_public_key(
        mallory_signing_private,
        mallory_exchange_public,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )

    forged_identity_accepted = verify_public_key_signature(
        alice_signing_public,
        mallory_exchange_public,
        mallory_signature,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )
    print("Mallory's signature accepted as Alice's:", forged_identity_accepted)

    # Test 3: Replace Alice's public key but retain Alice's signature.
    substituted_key_accepted = verify_public_key_signature(
        alice_signing_public,
        mallory_exchange_public,
        alice_signature,
        sender_id=b"Alice",
        recipient_id=b"Bob",
    )
    print("Substituted public key accepted:", substituted_key_accepted)


if __name__ == "__main__":
    test_authentication()
