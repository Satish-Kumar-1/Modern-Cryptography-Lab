
from cryptography.exceptions import InvalidTag

from key_exchange import generate_key_pair, derive_shared_secret
from key_derivation import derive_key
from encryption import encrypt_message, decrypt_message


def test_ciphertext_tampering():
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    shared_secret = derive_shared_secret(alice_private, bob_public)
    key = derive_key(shared_secret)

    nonce, ciphertext = encrypt_message(key, b"Integrity test")

    modified = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    try:
        decrypt_message(key, nonce, modified)
    except InvalidTag:
        print("Tampering detection: PASS")
        return

    print("Tampering detection: FAIL")


if __name__ == "__main__":
    test_ciphertext_tampering()
