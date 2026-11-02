import unittest

from cryptography.exceptions import InvalidSignature, InvalidTag

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
    validate_x25519_public_bytes,
    verify_signed_key_exchange_message,
)
from main import main
from scenarios import (
    run_authenticated_scenario,
    run_mitm_scenario,
    run_normal_scenario,
    run_tamper_scenario,
)


class TestDiffieHellmanProject(unittest.TestCase):
    def test_01_alice_and_bob_derive_matching_shared_secrets(self) -> None:
        alice_private, alice_public = generate_x25519_keypair()
        bob_private, bob_public = generate_x25519_keypair()

        alice_secret = compute_x25519_shared_secret(alice_private, bob_public)
        bob_secret = compute_x25519_shared_secret(bob_private, alice_public)

        self.assertEqual(len(alice_secret), 32)
        self.assertTrue(constant_time_compare(alice_secret, bob_secret))

    def test_02_raw_shared_secret_not_transmitted_and_differs_from_public_values(self) -> None:
        alice_private, alice_public = generate_x25519_keypair()
        bob_private, bob_public = generate_x25519_keypair()

        shared_secret = compute_x25519_shared_secret(alice_private, bob_public)
        self.assertFalse(constant_time_compare(shared_secret, alice_public))
        self.assertFalse(constant_time_compare(shared_secret, bob_public))

        outcome = run_normal_scenario(verbose=False)
        self.assertTrue(outcome.passed)
        self.assertTrue(outcome.details["shared_secrets_match"])

    def test_03_hkdf_returns_32_byte_key(self) -> None:
        alice_private, _ = generate_x25519_keypair()
        _, bob_public = generate_x25519_keypair()
        shared_secret = compute_x25519_shared_secret(alice_private, bob_public)

        salt = generate_salt()
        context = build_hkdf_context_info(
            protocol=PROTOCOL_ID,
            session_id=generate_session_id(),
            initiator="Alice",
            responder="Bob",
            purpose="encryption",
        )
        derived_key = derive_aes_key_with_hkdf(shared_secret, salt, context)
        self.assertIsInstance(derived_key, bytes)
        self.assertEqual(len(derived_key), AES_GCM_KEY_LENGTH)

    def test_04_different_hkdf_contexts_produce_different_derived_keys(self) -> None:
        alice_private, _ = generate_x25519_keypair()
        _, bob_public = generate_x25519_keypair()
        shared_secret = compute_x25519_shared_secret(alice_private, bob_public)
        salt = generate_salt()
        session_id = generate_session_id()

        context_enc = build_hkdf_context_info(
            protocol=PROTOCOL_ID,
            session_id=session_id,
            initiator="Alice",
            responder="Bob",
            purpose="client_to_server_aes_gcm",
        )
        context_mac = build_hkdf_context_info(
            protocol=PROTOCOL_ID,
            session_id=session_id,
            initiator="Alice",
            responder="Bob",
            purpose="server_to_client_aes_gcm",
        )

        key_enc = derive_aes_key_with_hkdf(shared_secret, salt, context_enc)
        key_mac = derive_aes_key_with_hkdf(shared_secret, salt, context_mac)
        self.assertFalse(constant_time_compare(key_enc, key_mac))

    def test_05_aes_gcm_encryption_and_decryption_recover_plaintext(self) -> None:
        alice_private, _ = generate_x25519_keypair()
        _, bob_public = generate_x25519_keypair()
        shared_secret = compute_x25519_shared_secret(alice_private, bob_public)
        key = derive_aes_key_with_hkdf(
            shared_secret,
            generate_salt(),
            build_hkdf_context_info(PROTOCOL_ID, generate_session_id(), "Alice", "Bob", "data"),
        )

        plaintext = b"Exact verification plaintext payload for AES-GCM test."
        aad = b"header:v1"
        encrypted = encrypt_aes_gcm(key, plaintext, aad)
        decrypted = decrypt_aes_gcm(key, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_06_invalid_public_key_lengths_and_types_are_rejected(self) -> None:
        alice_private, _ = generate_x25519_keypair()
        for invalid_length in (0, 1, 16, 31, 33, 64):
            with self.subTest(invalid_length=invalid_length):
                with self.assertRaises(ValueError):
                    validate_x25519_public_bytes(b"\x01" * invalid_length)
                with self.assertRaises(ValueError):
                    compute_x25519_shared_secret(alice_private, b"\x01" * invalid_length)

        with self.assertRaises(TypeError):
            validate_x25519_public_bytes("not-bytes-object")  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            compute_x25519_shared_secret(alice_private, b"\x00" * 32)

    def test_07_mitm_produces_two_independent_matching_connection_keys(self) -> None:
        outcome = run_mitm_scenario(verbose=False)
        self.assertTrue(outcome.passed)
        self.assertTrue(outcome.details["alice_mallory_secrets_match"])
        self.assertTrue(outcome.details["bob_mallory_secrets_match"])
        self.assertTrue(outcome.details["two_connections_distinct_secrets"])
        self.assertTrue(outcome.details["alice_mallory_keys_match"])
        self.assertTrue(outcome.details["bob_mallory_keys_match"])
        self.assertTrue(outcome.details["two_connections_distinct_keys"])

    def test_08_mallory_can_decrypt_and_relay_message_in_unauthenticated_mitm(self) -> None:
        outcome = run_mitm_scenario(verbose=False)
        self.assertTrue(outcome.passed)
        self.assertTrue(outcome.details["mallory_read_success"])
        self.assertTrue(outcome.details["bob_read_relayed_success"])

    def test_09_valid_ed25519_signatures_are_accepted(self) -> None:
        alice_sign_priv, alice_sign_pub = generate_ed25519_keypair()
        _, alice_eph_pub = generate_x25519_keypair()
        session_id = generate_session_id()
        registry = {"Alice": alice_sign_pub}

        signed_msg = create_signed_key_exchange_message(
            signing_private_key=alice_sign_priv,
            protocol=PROTOCOL_ID,
            sender="Alice",
            recipient="Bob",
            session_id=session_id,
            ephemeral_public_bytes=alice_eph_pub,
        )
        verified_bytes = verify_signed_key_exchange_message(
            message=signed_msg,
            trusted_registry=registry,
            expected_protocol=PROTOCOL_ID,
            expected_sender="Alice",
            expected_recipient="Bob",
            expected_session_id=session_id,
        )
        self.assertEqual(verified_bytes, alice_eph_pub)

    def test_10_altered_messages_and_invalid_signatures_are_rejected(self) -> None:
        alice_sign_priv, alice_sign_pub = generate_ed25519_keypair()
        mallory_sign_priv, _ = generate_ed25519_keypair()
        _, alice_eph_pub = generate_x25519_keypair()
        session_id = generate_session_id()
        registry = {"Alice": alice_sign_pub}

        forged_msg = create_signed_key_exchange_message(
            signing_private_key=mallory_sign_priv,
            protocol=PROTOCOL_ID,
            sender="Alice",
            recipient="Bob",
            session_id=session_id,
            ephemeral_public_bytes=alice_eph_pub,
        )
        with self.assertRaises(InvalidSignature):
            verify_signed_key_exchange_message(
                message=forged_msg,
                trusted_registry=registry,
                expected_protocol=PROTOCOL_ID,
                expected_sender="Alice",
                expected_recipient="Bob",
                expected_session_id=session_id,
            )

        valid_msg = create_signed_key_exchange_message(
            signing_private_key=alice_sign_priv,
            protocol=PROTOCOL_ID,
            sender="Alice",
            recipient="Bob",
            session_id=session_id,
            ephemeral_public_bytes=alice_eph_pub,
        )
        tampered_sig_msg = SignedKeyExchangeMessage(
            protocol=valid_msg.protocol,
            sender=valid_msg.sender,
            recipient=valid_msg.recipient,
            session_id=valid_msg.session_id,
            ephemeral_public_bytes=valid_msg.ephemeral_public_bytes,
            signature=flip_single_bit(valid_msg.signature, 0, 0),
        )
        with self.assertRaises(InvalidSignature):
            verify_signed_key_exchange_message(
                message=tampered_sig_msg,
                trusted_registry=registry,
                expected_protocol=PROTOCOL_ID,
                expected_sender="Alice",
                expected_recipient="Bob",
                expected_session_id=session_id,
            )

        with self.assertRaises(UntrustedIdentityError):
            verify_signed_key_exchange_message(
                message= create_signed_key_exchange_message(
                    signing_private_key=mallory_sign_priv,
                    protocol=PROTOCOL_ID,
                    sender="Mallory",
                    recipient="Bob",
                    session_id=session_id,
                    ephemeral_public_bytes=alice_eph_pub,
                ),
                trusted_registry=registry,
                expected_protocol=PROTOCOL_ID,
                expected_sender="Mallory",
                expected_recipient="Bob",
                expected_session_id=session_id,
            )

    def test_11_substituted_key_agreement_values_are_rejected_in_authenticated_scenario(self) -> None:
        alice_sign_priv, alice_sign_pub = generate_ed25519_keypair()
        _, alice_eph_pub = generate_x25519_keypair()
        _, mallory_eph_pub = generate_x25519_keypair()
        session_id = generate_session_id()
        registry = {"Alice": alice_sign_pub}

        alice_msg = create_signed_key_exchange_message(
            signing_private_key=alice_sign_priv,
            protocol=PROTOCOL_ID,
            sender="Alice",
            recipient="Bob",
            session_id=session_id,
            ephemeral_public_bytes=alice_eph_pub,
        )
        substituted_msg = SignedKeyExchangeMessage(
            protocol=alice_msg.protocol,
            sender=alice_msg.sender,
            recipient=alice_msg.recipient,
            session_id=alice_msg.session_id,
            ephemeral_public_bytes=mallory_eph_pub,
            signature=alice_msg.signature,
        )
        with self.assertRaises(InvalidSignature):
            verify_signed_key_exchange_message(
                message=substituted_msg,
                trusted_registry=registry,
                expected_protocol=PROTOCOL_ID,
                expected_sender="Alice",
                expected_recipient="Bob",
                expected_session_id=session_id,
            )

        outcome = run_authenticated_scenario(verbose=False)
        self.assertTrue(outcome.passed)
        self.assertTrue(outcome.details["substituted_key_rejected"])

    def test_12_aes_gcm_rejects_modified_ciphertext(self) -> None:
        alice_private, _ = generate_x25519_keypair()
        _, bob_public = generate_x25519_keypair()
        shared_secret = compute_x25519_shared_secret(alice_private, bob_public)
        key = derive_aes_key_with_hkdf(
            shared_secret,
            generate_salt(),
            build_hkdf_context_info(PROTOCOL_ID, generate_session_id(), "Alice", "Bob", "enc"),
        )
        encrypted = encrypt_aes_gcm(key, b"Sensitive message content", b"aad")
        tampered = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=flip_single_bit(encrypted.ciphertext, 2, 3),
            tag=encrypted.tag,
            associated_data=encrypted.associated_data,
        )
        with self.assertRaises(InvalidTag):
            decrypt_aes_gcm(key, tampered)

    def test_13_aes_gcm_rejects_modified_authentication_tag(self) -> None:
        alice_private, _ = generate_x25519_keypair()
        _, bob_public = generate_x25519_keypair()
        shared_secret = compute_x25519_shared_secret(alice_private, bob_public)
        key = derive_aes_key_with_hkdf(
            shared_secret,
            generate_salt(),
            build_hkdf_context_info(PROTOCOL_ID, generate_session_id(), "Alice", "Bob", "enc"),
        )
        encrypted = encrypt_aes_gcm(key, b"Sensitive message content", b"aad")
        tampered = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
            tag=flip_single_bit(encrypted.tag, 5, 1),
            associated_data=encrypted.associated_data,
        )
        with self.assertRaises(InvalidTag):
            decrypt_aes_gcm(key, tampered)

        outcome = run_tamper_scenario(verbose=False)
        self.assertTrue(outcome.passed)

    def test_14_session_id_and_recipient_binding_prevent_replay_or_redirection(self) -> None:
        alice_sign_priv, alice_sign_pub = generate_ed25519_keypair()
        _, alice_eph_pub = generate_x25519_keypair()
        session_id = generate_session_id()
        registry = {"Alice": alice_sign_pub}

        signed_msg = create_signed_key_exchange_message(
            signing_private_key=alice_sign_priv,
            protocol=PROTOCOL_ID,
            sender="Alice",
            recipient="Bob",
            session_id=session_id,
            ephemeral_public_bytes=alice_eph_pub,
        )
        with self.assertRaises(ProtocolValidationError):
            verify_signed_key_exchange_message(
                message=signed_msg,
                trusted_registry=registry,
                expected_protocol=PROTOCOL_ID,
                expected_sender="Alice",
                expected_recipient="Bob",
                expected_session_id=generate_session_id(),
            )
        with self.assertRaises(ProtocolValidationError):
            verify_signed_key_exchange_message(
                message=signed_msg,
                trusted_registry=registry,
                expected_protocol=PROTOCOL_ID,
                expected_sender="Alice",
                expected_recipient="Charlie",
                expected_session_id=session_id,
            )

    def test_15_cli_commands_and_invalid_arguments(self) -> None:
        self.assertEqual(main(["normal"]), 0)
        self.assertEqual(main(["mitm"]), 0)
        self.assertEqual(main(["authenticated"]), 0)
        self.assertEqual(main(["tamper"]), 0)
        self.assertEqual(main(["all"]), 0)
        self.assertNotEqual(main(["invalid_scenario_name"]), 0)


if __name__ == "__main__":
    unittest.main()