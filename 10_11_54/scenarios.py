from dataclasses import dataclass
from typing import Dict

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519

from crypto_utils import (
    AES_GCM_KEY_LENGTH,
    PROTOCOL_ID,
    EncryptedMessage,
    ProtocolValidationError,
    SignedKeyExchangeMessage,
    UntrustedIdentityError,
    build_hkdf_context_info,
    compute_x25519_shared_secret,
    constant_time_compare,
    create_signed_key_exchange_message,
    decrypt_aes_gcm,
    derive_aes_key_with_hkdf,
    encrypt_aes_gcm,
    flip_single_bit,
    generate_ed25519_keypair,
    generate_salt,
    generate_session_id,
    generate_x25519_keypair,
    verify_signed_key_exchange_message,
)


@dataclass(frozen=True)
class ScenarioOutcome:
    scenario_name: str
    passed: bool
    details: Dict[str, object]


def run_normal_scenario(verbose: bool = True) -> ScenarioOutcome:
    session_id = generate_session_id()
    salt = generate_salt()
    demo_plaintext = b"Confidential academic payload: Transfer authorization code 9481-ALPHA."
    associated_data = f"session:{session_id}".encode("utf-8")

    alice_private, alice_public_bytes = generate_x25519_keypair()
    bob_private, bob_public_bytes = generate_x25519_keypair()

    alice_shared_secret = compute_x25519_shared_secret(alice_private, bob_public_bytes)
    bob_shared_secret = compute_x25519_shared_secret(bob_private, alice_public_bytes)
    shared_secrets_match = constant_time_compare(alice_shared_secret, bob_shared_secret)

    encryption_context = build_hkdf_context_info(
        protocol=PROTOCOL_ID,
        session_id=session_id,
        initiator="Alice",
        responder="Bob",
        purpose="application_aes_gcm_encryption",
    )
    audit_context = build_hkdf_context_info(
        protocol=PROTOCOL_ID,
        session_id=session_id,
        initiator="Alice",
        responder="Bob",
        purpose="session_audit_subkey",
    )

    alice_app_key = derive_aes_key_with_hkdf(
        shared_secret=alice_shared_secret,
        salt=salt,
        context_info=encryption_context,
    )
    bob_app_key = derive_aes_key_with_hkdf(
        shared_secret=bob_shared_secret,
        salt=salt,
        context_info=encryption_context,
    )
    alice_audit_key = derive_aes_key_with_hkdf(
        shared_secret=alice_shared_secret,
        salt=salt,
        context_info=audit_context,
    )

    app_keys_match = constant_time_compare(alice_app_key, bob_app_key)
    domain_separation_verified = not constant_time_compare(alice_app_key, alice_audit_key)
    key_length_valid = len(alice_app_key) == AES_GCM_KEY_LENGTH

    encrypted_message = encrypt_aes_gcm(
        key=alice_app_key,
        plaintext=demo_plaintext,
        associated_data=associated_data,
    )
    recovered_plaintext = decrypt_aes_gcm(
        key=bob_app_key,
        encrypted_message=encrypted_message,
    )
    plaintext_matches = recovered_plaintext == demo_plaintext

    overall_pass = all(
        [
            shared_secrets_match,
            app_keys_match,
            domain_separation_verified,
            key_length_valid,
            plaintext_matches,
        ]
    )

    if verbose:
        print("=" * 72)
        print("SCENARIO A: NORMAL DIFFIE-HELLMAN KEY EXCHANGE (X25519 + HKDF + AES-GCM)")
        print("=" * 72)
        print(f"Session ID                  : {session_id}")
        print(f"Alice Public Key (hex)      : {alice_public_bytes.hex()}")
        print(f"Bob Public Key (hex)        : {bob_public_bytes.hex()}")
        print(f"Shared Secrets Match        : {'PASS' if shared_secrets_match else 'FAIL'}")
        print(f"Derived 32-Byte Keys Match  : {'PASS' if (app_keys_match and key_length_valid) else 'FAIL'}")
        print(f"HKDF Domain Separation      : {'PASS' if domain_separation_verified else 'FAIL'}")
        print(f"Original Plaintext          : {demo_plaintext.decode('utf-8')}")
        print(f"AES-GCM Nonce (hex)         : {encrypted_message.nonce.hex()}")
        print(f"AES-GCM Ciphertext (hex)    : {encrypted_message.ciphertext.hex()}")
        print(f"AES-GCM Auth Tag (hex)      : {encrypted_message.tag.hex()}")
        print(f"Decrypted Plaintext by Bob  : {recovered_plaintext.decode('utf-8')}")
        print(f"Message Integrity & Match   : {'PASS' if plaintext_matches else 'FAIL'}")
        print(f"Scenario A Overall Verdict  : {'[PASS]' if overall_pass else '[FAIL]'}")
        print()

    return ScenarioOutcome(
        scenario_name="normal",
        passed=overall_pass,
        details={
            "shared_secrets_match": shared_secrets_match,
            "app_keys_match": app_keys_match,
            "domain_separation_verified": domain_separation_verified,
            "key_length_valid": key_length_valid,
            "plaintext_matches": plaintext_matches,
            "recovered_plaintext": recovered_plaintext,
        },
    )


def run_mitm_scenario(verbose: bool = True) -> ScenarioOutcome:
    session_id = generate_session_id()
    salt = generate_salt()
    demo_plaintext = b"Classified laboratory report: Prototype deployment scheduled at 0400 UTC."
    associated_data = f"session:{session_id}".encode("utf-8")

    alice_private, alice_public_bytes = generate_x25519_keypair()
    bob_private, bob_public_bytes = generate_x25519_keypair()

    mallory_for_bob_private, mallory_for_bob_public_bytes = generate_x25519_keypair()
    mallory_for_alice_private, mallory_for_alice_public_bytes = generate_x25519_keypair()

    bob_secret_with_mallory = compute_x25519_shared_secret(
        bob_private, mallory_for_bob_public_bytes
    )
    mallory_secret_with_bob = compute_x25519_shared_secret(
        mallory_for_bob_private, bob_public_bytes
    )

    alice_secret_with_mallory = compute_x25519_shared_secret(
        alice_private, mallory_for_alice_public_bytes
    )
    mallory_secret_with_alice = compute_x25519_shared_secret(
        mallory_for_alice_private, alice_public_bytes
    )

    alice_mallory_secrets_match = constant_time_compare(
        alice_secret_with_mallory, mallory_secret_with_alice
    )
    bob_mallory_secrets_match = constant_time_compare(
        bob_secret_with_mallory, mallory_secret_with_bob
    )
    two_connections_distinct_secrets = not constant_time_compare(
        mallory_secret_with_alice, mallory_secret_with_bob
    )

    shared_context = build_hkdf_context_info(
        protocol=PROTOCOL_ID,
        session_id=session_id,
        initiator="Alice",
        responder="Bob",
        purpose="application_aes_gcm_encryption",
    )

    alice_key = derive_aes_key_with_hkdf(
        shared_secret=alice_secret_with_mallory,
        salt=salt,
        context_info=shared_context,
    )
    mallory_alice_key = derive_aes_key_with_hkdf(
        shared_secret=mallory_secret_with_alice,
        salt=salt,
        context_info=shared_context,
    )
    bob_key = derive_aes_key_with_hkdf(
        shared_secret=bob_secret_with_mallory,
        salt=salt,
        context_info=shared_context,
    )
    mallory_bob_key = derive_aes_key_with_hkdf(
        shared_secret=mallory_secret_with_bob,
        salt=salt,
        context_info=shared_context,
    )

    alice_mallory_keys_match = constant_time_compare(alice_key, mallory_alice_key)
    bob_mallory_keys_match = constant_time_compare(bob_key, mallory_bob_key)
    two_connections_distinct_keys = not constant_time_compare(
        mallory_alice_key, mallory_bob_key
    )

    alice_encrypted = encrypt_aes_gcm(
        key=alice_key,
        plaintext=demo_plaintext,
        associated_data=associated_data,
    )
    mallory_intercepted_plaintext = decrypt_aes_gcm(
        key=mallory_alice_key,
        encrypted_message=alice_encrypted,
    )
    mallory_read_success = mallory_intercepted_plaintext == demo_plaintext

    mallory_reencrypted_for_bob = encrypt_aes_gcm(
        key=mallory_bob_key,
        plaintext=mallory_intercepted_plaintext,
        associated_data=associated_data,
    )
    bob_received_plaintext = decrypt_aes_gcm(
        key=bob_key,
        encrypted_message=mallory_reencrypted_for_bob,
    )
    bob_read_relayed_success = bob_received_plaintext == demo_plaintext

    overall_pass = all(
        [
            alice_mallory_secrets_match,
            bob_mallory_secrets_match,
            two_connections_distinct_secrets,
            alice_mallory_keys_match,
            bob_mallory_keys_match,
            two_connections_distinct_keys,
            mallory_read_success,
            bob_read_relayed_success,
        ]
    )

    if verbose:
        print("=" * 72)
        print("SCENARIO B: UNAUTHENTICATED MAN-IN-THE-MIDDLE (MITM) ATTACK SIMULATION")
        print("=" * 72)
        print(f"Session ID                           : {session_id}")
        print(f"Alice Ephemeral Public (hex)         : {alice_public_bytes.hex()}")
        print(f"Mallory->Bob Substituted Public (hex): {mallory_for_bob_public_bytes.hex()}")
        print(f"Bob Ephemeral Public (hex)           : {bob_public_bytes.hex()}")
        print(f"Mallory->Alice Substituted Pub (hex) : {mallory_for_alice_public_bytes.hex()}")
        print(f"Alice-Mallory Secrets Match          : {'PASS' if alice_mallory_secrets_match else 'FAIL'}")
        print(f"Bob-Mallory Secrets Match            : {'PASS' if bob_mallory_secrets_match else 'FAIL'}")
        print(f"Two Connections Use Distinct Secrets : {'PASS' if two_connections_distinct_secrets else 'FAIL'}")
        print(f"Alice-Mallory Derived Keys Match     : {'PASS' if alice_mallory_keys_match else 'FAIL'}")
        print(f"Bob-Mallory Derived Keys Match       : {'PASS' if bob_mallory_keys_match else 'FAIL'}")
        print(f"Two Connections Use Distinct Keys    : {'PASS' if two_connections_distinct_keys else 'FAIL'}")
        print(f"Mallory Intercepted Plaintext        : {mallory_intercepted_plaintext.decode('utf-8')}")
        print(f"Bob Decrypted Relayed Plaintext      : {bob_received_plaintext.decode('utf-8')}")
        print(f"MITM Interception & Relay Verified   : {'PASS' if (mallory_read_success and bob_read_relayed_success) else 'FAIL'}")
        print(f"Scenario B Overall Verdict           : {'[PASS]' if overall_pass else '[FAIL]'}")
        print()

    return ScenarioOutcome(
        scenario_name="mitm",
        passed=overall_pass,
        details={
            "alice_mallory_secrets_match": alice_mallory_secrets_match,
            "bob_mallory_secrets_match": bob_mallory_secrets_match,
            "two_connections_distinct_secrets": two_connections_distinct_secrets,
            "alice_mallory_keys_match": alice_mallory_keys_match,
            "bob_mallory_keys_match": bob_mallory_keys_match,
            "two_connections_distinct_keys": two_connections_distinct_keys,
            "mallory_read_success": mallory_read_success,
            "bob_read_relayed_success": bob_read_relayed_success,
        },
    )


def run_authenticated_scenario(verbose: bool = True) -> ScenarioOutcome:
    session_id = generate_session_id()
    salt = generate_salt()
    demo_plaintext = b"Authenticated command: Authorize satellite telemetry downlink."
    associated_data = f"session:{session_id}".encode("utf-8")

    alice_id_private, alice_id_public = generate_ed25519_keypair()
    bob_id_private, bob_id_public = generate_ed25519_keypair()
    mallory_id_private, _ = generate_ed25519_keypair()

    trusted_registry: Dict[str, ed25519.Ed25519PublicKey] = {
        "Alice": alice_id_public,
        "Bob": bob_id_public,
    }

    alice_eph_private, alice_eph_public_bytes = generate_x25519_keypair()
    bob_eph_private, bob_eph_public_bytes = generate_x25519_keypair()

    alice_signed_msg = create_signed_key_exchange_message(
        signing_private_key=alice_id_private,
        protocol=PROTOCOL_ID,
        sender="Alice",
        recipient="Bob",
        session_id=session_id,
        ephemeral_public_bytes=alice_eph_public_bytes,
    )
    bob_signed_msg = create_signed_key_exchange_message(
        signing_private_key=bob_id_private,
        protocol=PROTOCOL_ID,
        sender="Bob",
        recipient="Alice",
        session_id=session_id,
        ephemeral_public_bytes=bob_eph_public_bytes,
    )

    verified_alice_pub = verify_signed_key_exchange_message(
        message=alice_signed_msg,
        trusted_registry=trusted_registry,
        expected_protocol=PROTOCOL_ID,
        expected_sender="Alice",
        expected_recipient="Bob",
        expected_session_id=session_id,
    )
    verified_bob_pub = verify_signed_key_exchange_message(
        message=bob_signed_msg,
        trusted_registry=trusted_registry,
        expected_protocol=PROTOCOL_ID,
        expected_sender="Bob",
        expected_recipient="Alice",
        expected_session_id=session_id,
    )

    alice_shared = compute_x25519_shared_secret(alice_eph_private, verified_bob_pub)
    bob_shared = compute_x25519_shared_secret(bob_eph_private, verified_alice_pub)

    context_info = build_hkdf_context_info(
        protocol=PROTOCOL_ID,
        session_id=session_id,
        initiator="Alice",
        responder="Bob",
        purpose="authenticated_aes_gcm_encryption",
    )
    alice_key = derive_aes_key_with_hkdf(alice_shared, salt, context_info)
    bob_key = derive_aes_key_with_hkdf(bob_shared, salt, context_info)
    authenticated_keys_match = constant_time_compare(alice_key, bob_key)

    encrypted_payload = encrypt_aes_gcm(alice_key, demo_plaintext, associated_data)
    decrypted_payload = decrypt_aes_gcm(bob_key, encrypted_payload)
    legitimate_exchange_succeeded = (
        authenticated_keys_match and decrypted_payload == demo_plaintext
    )

    _, mallory_eph_public_bytes = generate_x25519_keypair()

    substituted_key_msg = SignedKeyExchangeMessage(
        protocol=alice_signed_msg.protocol,
        sender=alice_signed_msg.sender,
        recipient=alice_signed_msg.recipient,
        session_id=alice_signed_msg.session_id,
        ephemeral_public_bytes=mallory_eph_public_bytes,
        signature=alice_signed_msg.signature,
    )
    substituted_key_rejected = False
    try:
        verify_signed_key_exchange_message(
            message=substituted_key_msg,
            trusted_registry=trusted_registry,
            expected_protocol=PROTOCOL_ID,
            expected_sender="Alice",
            expected_recipient="Bob",
            expected_session_id=session_id,
        )
    except InvalidSignature:
        substituted_key_rejected = True

    forged_signature_msg = create_signed_key_exchange_message(
        signing_private_key=mallory_id_private,
        protocol=PROTOCOL_ID,
        sender="Alice",
        recipient="Bob",
        session_id=session_id,
        ephemeral_public_bytes=mallory_eph_public_bytes,
    )
    forged_signature_rejected = False
    try:
        verify_signed_key_exchange_message(
            message=forged_signature_msg,
            trusted_registry=trusted_registry,
            expected_protocol=PROTOCOL_ID,
            expected_sender="Alice",
            expected_recipient="Bob",
            expected_session_id=session_id,
        )
    except InvalidSignature:
        forged_signature_rejected = True

    untrusted_identity_msg = create_signed_key_exchange_message(
        signing_private_key=mallory_id_private,
        protocol=PROTOCOL_ID,
        sender="Mallory",
        recipient="Bob",
        session_id=session_id,
        ephemeral_public_bytes=mallory_eph_public_bytes,
    )
    untrusted_identity_rejected = False
    try:
        verify_signed_key_exchange_message(
            message=untrusted_identity_msg,
            trusted_registry=trusted_registry,
            expected_protocol=PROTOCOL_ID,
            expected_sender="Mallory",
            expected_recipient="Bob",
            expected_session_id=session_id,
        )
    except UntrustedIdentityError:
        untrusted_identity_rejected = True

    modified_session_msg = SignedKeyExchangeMessage(
        protocol=alice_signed_msg.protocol,
        sender=alice_signed_msg.sender,
        recipient=alice_signed_msg.recipient,
        session_id=generate_session_id(),
        ephemeral_public_bytes=alice_signed_msg.ephemeral_public_bytes,
        signature=alice_signed_msg.signature,
    )
    modified_session_rejected = False
    try:
        verify_signed_key_exchange_message(
            message=modified_session_msg,
            trusted_registry=trusted_registry,
            expected_protocol=PROTOCOL_ID,
            expected_sender="Alice",
            expected_recipient="Bob",
            expected_session_id=session_id,
        )
    except (ProtocolValidationError, InvalidSignature):
        modified_session_rejected = True

    overall_pass = all(
        [
            legitimate_exchange_succeeded,
            substituted_key_rejected,
            forged_signature_rejected,
            untrusted_identity_rejected,
            modified_session_rejected,
        ]
    )

    if verbose:
        print("=" * 72)
        print("SCENARIO C: AUTHENTICATED KEY EXCHANGE (Ed25519 + TRUSTED REGISTRY)")
        print("=" * 72)
        print(f"Session ID                              : {session_id}")
        print(f"Trusted Registry Entities               : {', '.join(sorted(trusted_registry.keys()))}")
        print(f"Legitimate Signed Exchange & Decryption : {'PASS' if legitimate_exchange_succeeded else 'FAIL'}")
        print(f"Decrypted Authenticated Message         : {decrypted_payload.decode('utf-8')}")
        print(f"Attack 1 (Substituted Public Key)       : {'REJECTED [PASS]' if substituted_key_rejected else 'ACCEPTED [FAIL]'}")
        print(f"Attack 2 (Forged Signature by Mallory)  : {'REJECTED [PASS]' if forged_signature_rejected else 'ACCEPTED [FAIL]'}")
        print(f"Attack 3 (Untrusted Identity 'Mallory') : {'REJECTED [PASS]' if untrusted_identity_rejected else 'ACCEPTED [FAIL]'}")
        print(f"Attack 4 (Tampered Session Identifier)  : {'REJECTED [PASS]' if modified_session_rejected else 'ACCEPTED [FAIL]'}")
        print(f"Scenario C Overall Verdict              : {'[PASS]' if overall_pass else '[FAIL]'}")
        print()

    return ScenarioOutcome(
        scenario_name="authenticated",
        passed=overall_pass,
        details={
            "legitimate_exchange_succeeded": legitimate_exchange_succeeded,
            "substituted_key_rejected": substituted_key_rejected,
            "forged_signature_rejected": forged_signature_rejected,
            "untrusted_identity_rejected": untrusted_identity_rejected,
            "modified_session_rejected": modified_session_rejected,
        },
    )


def run_tamper_scenario(verbose: bool = True) -> ScenarioOutcome:
    session_id = generate_session_id()
    salt = generate_salt()
    demo_plaintext = b"Integrity-protected financial wire instruction: Account 883019, Amount $50,000."
    associated_data = f"session:{session_id}".encode("utf-8")

    alice_private, _ = generate_x25519_keypair()
    _, bob_public_bytes = generate_x25519_keypair()
    shared_secret = compute_x25519_shared_secret(alice_private, bob_public_bytes)

    context_info = build_hkdf_context_info(
        protocol=PROTOCOL_ID,
        session_id=session_id,
        initiator="Alice",
        responder="Bob",
        purpose="tamper_experiment_aes_gcm_key",
    )
    derived_key = derive_aes_key_with_hkdf(shared_secret, salt, context_info)

    original_encrypted = encrypt_aes_gcm(
        key=derived_key,
        plaintext=demo_plaintext,
        associated_data=associated_data,
    )
    second_encrypted = encrypt_aes_gcm(
        key=derived_key,
        plaintext=demo_plaintext,
        associated_data=associated_data,
    )
    nonces_unique = not constant_time_compare(
        original_encrypted.nonce, second_encrypted.nonce
    )

    unmodified_decrypted = decrypt_aes_gcm(derived_key, original_encrypted)
    unmodified_succeeded = unmodified_decrypted == demo_plaintext

    tampered_ciphertext_bytes = flip_single_bit(
        original_encrypted.ciphertext, byte_index=0, bit_index=0
    )
    tampered_ciphertext_message = EncryptedMessage(
        nonce=original_encrypted.nonce,
        ciphertext=tampered_ciphertext_bytes,
        tag=original_encrypted.tag,
        associated_data=original_encrypted.associated_data,
    )
    ciphertext_tamper_detected = False
    try:
        decrypt_aes_gcm(derived_key, tampered_ciphertext_message)
    except InvalidTag:
        ciphertext_tamper_detected = True

    tampered_tag_bytes = flip_single_bit(
        original_encrypted.tag, byte_index=0, bit_index=0
    )
    tampered_tag_message = EncryptedMessage(
        nonce=original_encrypted.nonce,
        ciphertext=original_encrypted.ciphertext,
        tag=tampered_tag_bytes,
        associated_data=original_encrypted.associated_data,
    )
    tag_tamper_detected = False
    try:
        decrypt_aes_gcm(derived_key, tampered_tag_message)
    except InvalidTag:
        tag_tamper_detected = True

    overall_pass = all(
        [
            nonces_unique,
            unmodified_succeeded,
            ciphertext_tamper_detected,
            tag_tamper_detected,
        ]
    )

    if verbose:
        print("=" * 72)
        print("SCENARIO D: AES-GCM AUTHENTICATED ENCRYPTION & TAMPERING DETECTION")
        print("=" * 72)
        print(f"Session ID                              : {session_id}")
        print(f"12-Byte Nonce Uniqueness Check          : {'PASS' if nonces_unique else 'FAIL'}")
        print(f"Unmodified Ciphertext Decryption        : {'PASS' if unmodified_succeeded else 'FAIL'}")
        print(f"Recovered Unmodified Plaintext          : {unmodified_decrypted.decode('utf-8')}")
        print(f"1-Bit Ciphertext Flip Detection         : {'REJECTED (InvalidTag) [PASS]' if ciphertext_tamper_detected else 'ACCEPTED [FAIL]'}")
        print(f"1-Bit Authentication Tag Flip Detection : {'REJECTED (InvalidTag) [PASS]' if tag_tamper_detected else 'ACCEPTED [FAIL]'}")
        print(f"Scenario D Overall Verdict              : {'[PASS]' if overall_pass else '[FAIL]'}")
        print()

    return ScenarioOutcome(
        scenario_name="tamper",
        passed=overall_pass,
        details={
            "nonces_unique": nonces_unique,
            "unmodified_succeeded": unmodified_succeeded,
            "ciphertext_tamper_detected": ciphertext_tamper_detected,
            "tag_tamper_detected": tag_tamper_detected,
        },
    )