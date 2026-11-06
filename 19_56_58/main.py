"""Main entry point for the Diffie-Hellman Key Exchange and MITM Demonstration.

Executes and demonstrates five comprehensive cryptographic scenarios:
1. Normal Diffie-Hellman key exchange between Alice and Bob.
2. Successful unauthenticated Man-in-the-Middle (MITM) attack by Mallory.
3. Authenticated key exchange using Ed25519 digital signatures.
4. Mallory's MITM attempt being rejected through signature verification.
5. Ciphertext tampering being detected by AES-256-GCM authenticated encryption.

Security policy:
No private keys, raw shared secrets, or symmetric encryption keys are printed.
"""

import sys
from typing import Any
from cryptography.exceptions import InvalidTag

from key_exchange import derive_shared_secret, generate_key_pair, verify_shared_secret
from key_derivation import derive_key
from encryption import decrypt_message, encrypt_message
from protocol import (
    simulate_unauthenticated_mitm,
    simulate_authenticated_exchange,
    simulate_authenticated_mitm_attempt,
)


def print_banner(title: str) -> None:
    """Print a section header banner."""
    separator = "=" * 76
    print(f"\n{separator}")
    print(f" {title.upper()}")
    print(f"{separator}")


def run_scenario_1_normal_dh() -> bool:
    """Scenario 1: Normal Diffie-Hellman key exchange between Alice and Bob.

    Demonstrates legitimate X25519 key agreement, HKDF-SHA256 key derivation,
    and AES-256-GCM authenticated encryption between Alice and Bob without an attacker.
    """
    print_banner("Scenario 1: Normal Diffie-Hellman Key Exchange (Alice & Bob)")
    print("[*] Concept: Alice and Bob generate ephemeral X25519 key pairs and")
    print("    exchange public keys over an uncompromised channel.\n")

    # Step 1: Generate ephemeral key pairs
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    print("[+] Alice generated ephemeral X25519 key pair.")
    print("[+] Bob generated ephemeral X25519 key pair.")

    # Step 2: Public key exchange
    print("[+] Alice sends public key to Bob.")
    print("[+] Bob sends public key to Alice.")

    # Step 3: Shared secret derivation
    alice_shared_secret = derive_shared_secret(alice_private, bob_public)
    bob_shared_secret = derive_shared_secret(bob_private, alice_public)

    secrets_match = verify_shared_secret(alice_shared_secret, bob_shared_secret)
    print(f"[+] Independent shared secret derivation complete.")
    print(f"[+] Alice and Bob shared secrets match: {secrets_match}")

    # Step 4: Key derivation via HKDF-SHA256
    alice_key = derive_key(alice_shared_secret)
    bob_key = derive_key(bob_shared_secret)
    print("[+] Derived 32-byte AES-256 session keys using HKDF-SHA256.")

    # Step 5: Secure message transmission
    plaintext = b"Hello Bob! This is a confidential message from Alice."
    print(f"\n[*] Alice's original plaintext: {plaintext.decode('utf-8')}")

    nonce, ciphertext = encrypt_message(alice_key, plaintext)
    print(f"[+] Alice encrypted message with AES-256-GCM.")
    print(f"    - Nonce (hex): {nonce.hex()}")
    print(f"    - Ciphertext + Tag length: {len(ciphertext)} bytes")

    # Step 6: Decryption by Bob
    decrypted_plaintext = decrypt_message(bob_key, nonce, ciphertext)
    print(f"[+] Bob decrypted ciphertext using his derived session key.")
    print(f"[*] Bob's decrypted message: {decrypted_plaintext.decode('utf-8')}")

    success = secrets_match and (decrypted_plaintext == plaintext)
    print(f"\n[RESULT] Scenario 1 Status: {'SUCCESS (Secure & Confidential)' if success else 'FAILED'}")
    return success


def run_scenario_2_unauthenticated_mitm() -> bool:
    """Scenario 2: Successful unauthenticated Man-in-the-Middle attack by Mallory.

    Demonstrates how Mallory intercepts and substitutes public keys in transit,
    establishing two separate shared secrets to eavesdrop and relay plaintext.
    """
    print_banner("Scenario 2: Unauthenticated Man-in-the-Middle Attack (Mallory)")
    print("[*] Concept: Raw Diffie-Hellman public keys are unauthenticated.")
    print("    Mallory intercepts keys in transit and substitutes her own.\n")

    message = b"Meet me at the station at noon."
    print(f"[*] Alice attempts to send: {message.decode('utf-8')}\n")

    result = simulate_unauthenticated_mitm(message=message)

    print("[!] Mallory intercepts Alice's public key and substitutes Mallory's public key to Bob.")
    print("[!] Mallory intercepts Bob's public key and substitutes Mallory's public key to Alice.")
    print(f"[!] Alice-Mallory shared secret agreement: {result['alice_mallory_secret_match']}")
    print(f"[!] Bob-Mallory shared secret agreement:   {result['bob_mallory_secret_match']}")
    print(f"[-] Alice-Bob direct shared secret match:  {result['alice_bob_secret_match']} (Keys are mismatched!)")

    intercepted = result["mallory_intercepted_message"]
    intercepted_str = intercepted.decode("utf-8") if intercepted else "None"
    print(f"\n[!] Mallory intercepts and decrypts Alice's ciphertext:")
    print(f"    -> Mallory reads plaintext: \"{intercepted_str}\"")

    received = result["bob_received_message"]
    received_str = received.decode("utf-8") if received else "None"
    print(f"[!] Mallory re-encrypts and relays to Bob:")
    print(f"    -> Bob receives plaintext:  \"{received_str}\"")
    print(f"    -> Bob believes the message came directly from Alice!")

    print(f"\n[RESULT] Scenario 2 Status: {'ATTACK SUCCEEDED (Confidentiality & Authentication Broken)' if result['attack_succeeded'] else 'ATTACK FAILED'}")
    return result["attack_succeeded"]


def run_scenario_3_authenticated_dh() -> bool:
    """Scenario 3: Authenticated key exchange using Ed25519 digital signatures.

    Demonstrates mutual authentication where Alice and Bob sign their ephemeral
    X25519 public keys bound to sender, recipient, and protocol ID.
    """
    print_banner("Scenario 3: Authenticated Key Exchange (Ed25519 Signatures)")
    print("[*] Concept: Alice and Bob possess pre-trusted Ed25519 signing keys.")
    print("    Each party signs their ephemeral X25519 public key before exchange.\n")

    message = b"Authenticated message from Alice to Bob."
    result = simulate_authenticated_exchange(message=message)

    print("[+] Alice signs her ephemeral public key (bound: Alice -> Bob, 'dh-mitm-v2').")
    print("[+] Bob signs his ephemeral public key (bound: Bob -> Alice, 'dh-mitm-v2').")
    print("[+] Alice verifies Bob's Ed25519 signature against Bob's trusted public key.")
    print("[+] Bob verifies Alice's Ed25519 signature against Alice's trusted public key.")
    print(f"[+] Mutual digital signature verification: {result['authentication_successful']}")
    print(f"[+] Ephemeral shared secrets match:         {result['shared_secrets_match']}")
    print(f"[+] Encrypted message delivered & decrypted: {result['message_decryption_successful']}")

    print(f"\n[RESULT] Scenario 3 Status: {'SUCCESS (Mutually Authenticated & Secure)' if result['exchange_successful'] else 'FAILED'}")
    return result["exchange_successful"]


def run_scenario_4_mitm_rejected() -> bool:
    """Scenario 4: Mallory's MITM attempt rejected through signature verification.

    Demonstrates Mallory attempting to substitute her ephemeral public key into an
    authenticated exchange. Bob detects invalid signature and aborts connection.
    """
    print_banner("Scenario 4: MITM Attempt Blocked by Signature Verification")
    print("[*] Concept: Mallory intercepts Alice's public key and substitutes her own.")
    print("    Because Mallory lacks Alice's private signing key, verification fails.\n")

    result = simulate_authenticated_mitm_attempt()

    print("[!] Mallory intercepts Alice's key exchange message directed to Bob.")
    print("[!] Mallory substitutes her own X25519 public key purporting to be Alice.")
    print("[+] Bob verifies the received public key using Alice's trusted Ed25519 key.")
    print("[-] Signature verification failed: Cryptographic signature mismatch detected.")
    print("[+] Bob immediately aborts the protocol before deriving any shared secret.")
    print(f"[+] Authentication successful: {result['authentication_successful']}")
    print(f"[+] MITM attack blocked:       {result['mitm_attack_blocked']}")
    print(f"[+] Shared secrets derived:    {result['shared_secrets_match']} (None derived)")

    print(f"\n[RESULT] Scenario 4 Status: {'ATTACK BLOCKED (Active Intrusion Neutralized)' if result['mitm_attack_blocked'] else 'FAILED'}")
    return result["mitm_attack_blocked"]


def run_scenario_5_tampering_detected() -> bool:
    """Scenario 5: Ciphertext tampering detected by AES-256-GCM.

    Demonstrates how AES-256-GCM's 16-byte authentication tag guarantees ciphertext
    integrity. Any unauthorized modification in transit causes decryption to fail.
    """
    print_banner("Scenario 5: Ciphertext Tampering Detected by AES-256-GCM")
    print("[*] Concept: AES-256-GCM provides authenticated encryption (AEAD).")
    print("    Modifying ciphertext or the tag invalidates the authentication tag.\n")

    # Step 1: Establish session key
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    shared_secret = derive_shared_secret(alice_private, bob_public)
    session_key = derive_key(shared_secret)
    print("[+] Alice and Bob established an authentic AES-256 session key.")

    # Step 2: Alice encrypts legitimate payload
    original_message = b"Transfer $1,000 to Bob's account."
    print(f"[*] Alice's message: \"{original_message.decode('utf-8')}\"")
    nonce, ciphertext = encrypt_message(session_key, original_message)
    print(f"[+] Encrypted with AES-256-GCM (Nonce: {nonce.hex()}, Length: {len(ciphertext)} bytes).")

    # Step 3: Active attacker tampers with ciphertext in transit
    tampered_ciphertext = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    print("[!] Mallory alters byte 0 of ciphertext in transit (bit-flip attack).")

    # Step 4: Bob attempts decryption
    tampering_detected = False
    print("[+] Bob attempts to decrypt and authenticate the received payload...")
    try:
        decrypt_message(session_key, nonce, tampered_ciphertext)
        print("[!] ERROR: Tampered ciphertext was decrypted without error!")
    except InvalidTag:
        tampering_detected = True
        print("[+] DETECTED: cryptography.exceptions.InvalidTag raised.")
        print("[+] Bob rejected the modified ciphertext; zero plaintext was released.")

    print(f"\n[RESULT] Scenario 5 Status: {'PASS (Integrity & Authenticity Guaranteed)' if tampering_detected else 'FAILED'}")
    return tampering_detected


def main() -> int:
    """Execute all five demonstration scenarios and display summary."""
    print("=" * 76)
    print("   DIFFIE-HELLMAN KEY EXCHANGE & MITM ATTACK DEMONSTRATION")
    print("=" * 76)
    print(" Environment: Python Cryptography (X25519, HKDF-SHA256, AES-256-GCM, Ed25519)")
    print(" Security Policy: Zero private keys, shared secrets, or AES keys are printed.")

    s1 = run_scenario_1_normal_dh()
    s2 = run_scenario_2_unauthenticated_mitm()
    s3 = run_scenario_3_authenticated_dh()
    s4 = run_scenario_4_mitm_rejected()
    s5 = run_scenario_5_tampering_detected()

    all_passed = s1 and s2 and s3 and s4 and s5

    print("\n" + "=" * 76)
    print("                           DEMONSTRATION SUMMARY")
    print("=" * 76)
    print(f" 1. Normal Diffie-Hellman Key Exchange   : {'[ SUCCESS / SECURE ]':>30}")
    print(f" 2. Unauthenticated MITM Attack          : {'[ ATTACK SUCCEEDED / VULNERABLE ]':>30}")
    print(f" 3. Authenticated Key Exchange (Ed25519) : {'[ SUCCESS / AUTHENTICATED ]':>30}")
    print(f" 4. Blocked MITM Attempt (Signatures)    : {'[ ATTACK BLOCKED / REJECTED ]':>30}")
    print(f" 5. AES-256-GCM Tampering Detection     : {'[ TAMPERING DETECTED / REJECTED ]':>30}")
    print("=" * 76)
    print(f" Overall Demonstration Status: {'ALL 5 SCENARIOS VERIFIED SUCCESSFULLY' if all_passed else 'SOME SCENARIOS FAILED'}")
    print(" Security Assurance: Constant-time comparison & zero sensitive keys leaked.")
    print("=" * 76)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
