from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag
import os


# ---------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------

# Convert a public key to raw bytes (this is what is "sent" over the network)
def public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


# Convert received bytes back into a public key, rejecting bad input
def load_public_key(raw):
    if len(raw) != 32:
        raise ValueError(f"wrong length ({len(raw)} bytes, expected 32)")
    return x25519.X25519PublicKey.from_public_bytes(raw)


# Compute the shared secret, rejecting invalid (low-order) public keys
def get_shared_secret(private_key, peer_public_key):
    try:
        return private_key.exchange(peer_public_key)
    except ValueError:
        raise ValueError("invalid public key (low-order point)")


# Derive a 32-byte AES key from the shared secret.
# 'purpose' gives each key its own label (domain separation).
def derive_key(secret, salt, purpose):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"DH project | " + purpose
    ).derive(secret)


# NEW: ask the user to type a message. Pressing Enter with nothing
# typed uses the default message instead.
def ask_message(prompt, default):
    text = input(f"{prompt} (Enter = \"{default}\"): ").strip()
    if text == "":
        text = default
    return text.encode()


# ---------------------------------------------------------------
# OPTION 1: Normal Diffie-Hellman exchange
# ---------------------------------------------------------------
def option1():
    print("\n=== OPTION 1: NORMAL KEY EXCHANGE ===")

    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()

    # Public values sent over the network as bytes (salt is public too)
    alice_sends = public_bytes(alice_private.public_key())
    bob_sends = public_bytes(bob_private.public_key())
    salt = os.urandom(16)
    print("Alice sends her public key:", alice_sends.hex()[:16], "...")
    print("Bob sends his public key:  ", bob_sends.hex()[:16], "...")

    try:
        alice_secret = get_shared_secret(alice_private, load_public_key(bob_sends))
        bob_secret = get_shared_secret(bob_private, load_public_key(alice_sends))
    except ValueError as error:
        print("Exchange aborted:", error)
        return

    # Only the comparison result is printed, never the secret itself
    print("\nShared secrets match:", alice_secret == bob_secret)

    alice_key = derive_key(alice_secret, salt, b"alice-to-bob encryption")
    bob_key = derive_key(bob_secret, salt, b"alice-to-bob encryption")
    print("HKDF keys match:", alice_key == bob_key)

    # CHANGED: Alice's message is typed by the user
    message = ask_message("\nType Alice's message to Bob",
                          "Hello Bob! This is a secure message.")
    nonce = os.urandom(12)
    ciphertext = AESGCM(alice_key).encrypt(nonce, message, None)
    print("\nEncrypted message:", ciphertext.hex())

    try:
        decrypted = AESGCM(bob_key).decrypt(nonce, ciphertext, None)
        print("Bob received:", decrypted.decode())
        print("Message received correctly:", decrypted == message)
    except InvalidTag:
        print("Decryption failed.")


# ---------------------------------------------------------------
# OPTION 2: Man-in-the-Middle attack (no authentication)
# ---------------------------------------------------------------
def option2():
    print("\n=== OPTION 2: MITM ATTACK ===")

    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()
    salt = os.urandom(16)

    # Mallory creates one key pair for Alice and one for Bob
    mallory_a_private = x25519.X25519PrivateKey.generate()
    mallory_b_private = x25519.X25519PrivateKey.generate()

    alice_sends = public_bytes(alice_private.public_key())
    bob_sends = public_bytes(bob_private.public_key())

    # Mallory intercepts and swaps in her own public keys
    print("Mallory intercepts Alice's key and sends her own to Bob.")
    print("Mallory intercepts Bob's key and sends her own to Alice.")
    bob_receives = public_bytes(mallory_b_private.public_key())
    alice_receives = public_bytes(mallory_a_private.public_key())

    # Each side computes a secret with what it received
    alice_secret = get_shared_secret(alice_private, load_public_key(alice_receives))
    bob_secret = get_shared_secret(bob_private, load_public_key(bob_receives))

    # Mallory computes both secrets (she saw the real public keys)
    mallory_secret_a = get_shared_secret(mallory_a_private, load_public_key(alice_sends))
    mallory_secret_b = get_shared_secret(mallory_b_private, load_public_key(bob_sends))

    print("\nAlice-Mallory secret matches:", alice_secret == mallory_secret_a)
    print("Bob-Mallory secret matches:  ", bob_secret == mallory_secret_b)
    print("Alice-Bob secrets match:     ", alice_secret == bob_secret)

    purpose = b"alice-to-bob encryption"
    alice_key = derive_key(alice_secret, salt, purpose)
    bob_key = derive_key(bob_secret, salt, purpose)
    mallory_key_a = derive_key(mallory_secret_a, salt, purpose)
    mallory_key_b = derive_key(mallory_secret_b, salt, purpose)

    # CHANGED: Alice's message is typed by the user
    message = ask_message("\nType Alice's message to Bob",
                          "Meet me at the library at 5 PM.")
    nonce1 = os.urandom(12)
    ciphertext = AESGCM(alice_key).encrypt(nonce1, message, None)

    # Mallory decrypts and reads it
    stolen = AESGCM(mallory_key_a).decrypt(nonce1, ciphertext, None)
    print("\nMallory reads:", stolen.decode())

    # CHANGED: the altered message is typed by the user (acting as Mallory)
    changed = ask_message("Type the changed message Mallory sends to Bob",
                          stolen.replace(b"5 PM", b"9 PM").decode())
    nonce2 = os.urandom(12)
    relayed = AESGCM(mallory_key_b).encrypt(nonce2, changed, None)
    print("Mallory changes the message and forwards it to Bob.")

    received = AESGCM(bob_key).decrypt(nonce2, relayed, None)
    print("\nBob receives (no error):", received.decode())
    print("Bob got Alice's real message:", received == message)
    print("Neither Alice nor Bob can detect the attack.")


# ---------------------------------------------------------------
# OPTION 3: Authenticated key exchange (signed public keys)
# ---------------------------------------------------------------

# Check a signature using a previously trusted public key
def check_signature(trusted_key, signature, data, name):
    try:
        trusted_key.verify(signature, data)
        print(f"  {name}'s signature is valid -> accepted")
        return True
    except InvalidSignature:
        print(f"  {name}'s signature is INVALID -> exchange aborted")
        return False


def option3():
    print("\n=== OPTION 3: AUTHENTICATED KEY EXCHANGE ===")

    # Long-term signing keys. We assume Alice and Bob exchanged their
    # verification keys earlier over a trusted channel.
    alice_signing = ed25519.Ed25519PrivateKey.generate()
    bob_signing = ed25519.Ed25519PrivateKey.generate()
    alice_verify = alice_signing.public_key()   # trusted by Bob
    bob_verify = bob_signing.public_key()       # trusted by Alice

    # Mallory has her own keys, but NOT Alice's or Bob's signing keys
    mallory_signing = ed25519.Ed25519PrivateKey.generate()
    mallory_public = public_bytes(x25519.X25519PrivateKey.generate().public_key())

    # Fresh Diffie-Hellman keys for this session
    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()
    a_pub = public_bytes(alice_private.public_key())
    b_pub = public_bytes(bob_private.public_key())

    # Alice signs her public key; Bob signs both public keys
    alice_data = b"Alice-to-Bob" + a_pub
    bob_data = b"Bob-to-Alice" + a_pub + b_pub
    alice_signature = alice_signing.sign(alice_data)
    bob_signature = bob_signing.sign(bob_data)

    results = []

    # --- A: Honest exchange ---
    print("\n--- A. Honest exchange (no attacker) ---")
    ok = (check_signature(alice_verify, alice_signature, alice_data, "Alice") and
          check_signature(bob_verify, bob_signature, bob_data, "Bob"))
    if ok:
        alice_secret = get_shared_secret(alice_private, load_public_key(b_pub))
        bob_secret = get_shared_secret(bob_private, load_public_key(a_pub))
        print("  Shared secrets match:", alice_secret == bob_secret)

        salt = os.urandom(16)
        alice_key = derive_key(alice_secret, salt, b"alice-to-bob encryption")
        bob_key = derive_key(bob_secret, salt, b"alice-to-bob encryption")

        # CHANGED: Alice's message is typed by the user
        message = ask_message("  Type Alice's message to Bob",
                              "Authenticated message for Bob.")
        nonce = os.urandom(12)
        ciphertext = AESGCM(alice_key).encrypt(nonce, message, None)
        decrypted = AESGCM(bob_key).decrypt(nonce, ciphertext, None)
        print("  Bob received:", decrypted.decode())
        print("  Message received correctly:", decrypted == message)
    results.append(("A. Honest exchange", ok))

    # --- B: Mallory swaps Alice's key but keeps Alice's signature ---
    print("\n--- B. Mallory swaps Alice's key, keeps Alice's signature ---")
    fake_data = b"Alice-to-Bob" + mallory_public
    ok = check_signature(alice_verify, alice_signature, fake_data, "Alice")
    results.append(("B. Swap Alice's key, keep her signature", ok))

    # --- C: Mallory swaps Alice's key and signs it with her own key ---
    print("\n--- C. Mallory swaps Alice's key and signs it herself ---")
    fake_data = b"Alice-to-Bob" + mallory_public
    fake_signature = mallory_signing.sign(fake_data)
    ok = check_signature(alice_verify, fake_signature, fake_data, "Alice")
    results.append(("C. Swap Alice's key, Mallory signs it", ok))

    # --- D: Mallory swaps Bob's key but keeps Bob's signature ---
    print("\n--- D. Mallory swaps Bob's key, keeps Bob's signature ---")
    fake_data = b"Bob-to-Alice" + a_pub + mallory_public
    ok = check_signature(bob_verify, bob_signature, fake_data, "Bob")
    results.append(("D. Swap Bob's key, keep his signature", ok))

    # --- E: Mallory changes one bit of Alice's signature ---
    print("\n--- E. Mallory corrupts Alice's signature ---")
    broken = bytearray(alice_signature)
    broken[0] ^= 1
    ok = check_signature(alice_verify, bytes(broken), alice_data, "Alice")
    results.append(("E. Corrupted signature", ok))

    print("\n--- Summary ---")
    for name, ok in results:
        print(f"  {name:<42} {'ACCEPTED' if ok else 'REJECTED'}")


# ---------------------------------------------------------------
# OPTION 4: Message tampering detection
# ---------------------------------------------------------------

# Try to decrypt and report whether AES-GCM accepted or rejected it
def try_decrypt(label, key, nonce, data):
    try:
        AESGCM(key).decrypt(nonce, data, None)
        print(f"  {label:<32} ACCEPTED")
    except InvalidTag:
        print(f"  {label:<32} REJECTED (InvalidTag)")


def option4():
    print("\n=== OPTION 4: MESSAGE TAMPERING TEST ===")

    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()
    alice_secret = get_shared_secret(alice_private, bob_private.public_key())
    bob_secret = get_shared_secret(bob_private, alice_private.public_key())

    salt = os.urandom(16)
    alice_key = derive_key(alice_secret, salt, b"alice-to-bob encryption")
    bob_key = derive_key(bob_secret, salt, b"alice-to-bob encryption")

    # CHANGED: the message is typed by the user
    message = ask_message("Type Alice's message to Bob",
                          "Do not modify this message.")
    nonce = os.urandom(12)
    ciphertext = AESGCM(alice_key).encrypt(nonce, message, None)

    # AES-GCM output = encrypted message + 16-byte authentication tag
    print("Encrypted part:", ciphertext[:-16].hex())
    print("Tag (16 bytes):", ciphertext[-16:].hex())
    print()

    try_decrypt("Original message", bob_key, nonce, ciphertext)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1                       # change first byte of message
    try_decrypt("Ciphertext byte modified", bob_key, nonce, bytes(tampered))

    tampered = bytearray(ciphertext)
    tampered[-1] ^= 1                      # change last byte of tag
    try_decrypt("Authentication tag modified", bob_key, nonce, bytes(tampered))

    wrong_nonce = bytearray(nonce)
    wrong_nonce[0] ^= 1
    try_decrypt("Nonce modified", bob_key, bytes(wrong_nonce), ciphertext)

    print("\nAES-GCM checks the tag before decrypting, so any change is detected.")


# ---------------------------------------------------------------
# OPTION 5: Invalid key-agreement values
# ---------------------------------------------------------------
def option5():
    print("\n=== OPTION 5: INVALID KEY-AGREEMENT VALUES ===")

    bob_private = x25519.X25519PrivateKey.generate()
    valid_key = public_bytes(x25519.X25519PrivateKey.generate().public_key())

    tests = [
        ("Valid public key", valid_key),
        ("Too short (5 bytes)", b"\x01" * 5),
        ("Too long (33 bytes)", valid_key + b"\x00"),
        ("All zeros (low-order point)", b"\x00" * 32),
    ]

    for label, raw in tests:
        try:
            peer_key = load_public_key(raw)
            get_shared_secret(bob_private, peer_key)
            print(f"  {label:<30} ACCEPTED")
        except ValueError as error:
            print(f"  {label:<30} REJECTED ({error})")


# ---------------------------------------------------------------
# OPTION 6: HKDF and domain separation
# ---------------------------------------------------------------
def option6():
    print("\n=== OPTION 6: HKDF AND DOMAIN SEPARATION ===")
    print("Why HKDF? The raw DH secret is not uniformly random, so it is")
    print("not used directly as a key. HKDF turns it into strong keys, and")
    print("the 'info' label lets us make a different key for each purpose.\n")

    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()
    secret = get_shared_secret(alice_private, bob_private.public_key())
    salt = os.urandom(16)

    key_a2b = derive_key(secret, salt, b"alice-to-bob encryption")
    key_b2a = derive_key(secret, salt, b"bob-to-alice encryption")
    key_again = derive_key(secret, salt, b"alice-to-bob encryption")

    print("Same secret, different labels -> different keys:", key_a2b != key_b2a)
    print("Same secret, same label -> same key:            ", key_a2b == key_again)
    print("Derived key differs from raw secret:            ", key_a2b != secret)

    # CHANGED: the message is typed by the user
    message = ask_message("\nType Alice's message to Bob", "Alice to Bob")

    # A message encrypted for one purpose cannot be opened with the other key
    nonce = os.urandom(12)
    ciphertext = AESGCM(key_a2b).encrypt(nonce, message, None)
    try:
        AESGCM(key_b2a).decrypt(nonce, ciphertext, None)
        print("\nOpened with the wrong-purpose key: True")
    except InvalidTag:
        print("\nAlice->Bob message cannot be opened with the Bob->Alice key.")
        print("So a message cannot be reflected back and accepted as Bob's.")


# ---------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------
while True:
    print("\n========================================")
    print(" DIFFIE-HELLMAN KEY EXCHANGE PROJECT")
    print("========================================")
    print("1. Normal Key Exchange")
    print("2. MITM Attack Simulation")
    print("3. Authenticated Key Exchange")
    print("4. Message Tampering Test")
    print("5. Invalid Key Values Test")
    print("6. HKDF / Domain Separation")
    print("7. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        option1()
    elif choice == "2":
        option2()
    elif choice == "3":
        option3()
    elif choice == "4":
        option4()
    elif choice == "5":
        option5()
    elif choice == "6":
        option6()
    elif choice == "7":
        print("Exiting program.")
        break
    else:
        print("Invalid choice. Please try again.")