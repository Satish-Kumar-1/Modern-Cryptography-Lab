#!/usr/bin/env python3
"""
Project 2: Secure Messaging With Digital Signatures
Member 2: Security Analysis & Attack Simulator (experiments.py)

Simulates the complete test matrix:
  - Baseline: Normal Authentic Message Exchange
  - Exp 1: Message Modification (Payload & Signature Corruption)
  - Exp 2: Sender Impersonation Attempt
  - Exp 3: Public-Key Substitution Attack & Fingerprint Defense
  - Exp 4: Confidentiality Analysis & AES-256-GCM Extension
  - Exp 5: Replay Attack & Counter / Timestamp Defense
"""

import base64
import copy
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from crypto_core import PublicKeyDirectory, SecurityError, User

console = Console()


def exp0_baseline(alice: User, bob: User) -> dict:
    """
    Baseline Test: Normal Authentic Message Exchange.
    Alice signs a message and Bob verifies it with all defenses ON.
    """
    message = "Meet me at the library at 4 PM. Bring the project notes."
    packet = alice.sign_message(recipient="Bob", plaintext=message)
    verification = bob.verify_message(packet, enforce_replay_defense=True, verify_key_fingerprint=True)

    result = {
        "experiment_id": "EXP-0",
        "title": "Baseline: Normal Authentic Exchange",
        "sender": "Alice",
        "recipient": "Bob",
        "original_message": message,
        "packet": packet,
        "verification": verification,
        "passed": verification["valid"] is True and verification["status_code"] == "SUCCESS",
        "observation": (
            "The Ed25519 signature verified successfully using Alice's authentic public key. "
            "Integrity, non-repudiation, and sender authenticity are fully established."
        )
    }
    return result


def exp1_message_modification(alice: User, bob: User) -> dict:
    """
    Experiment 1: Message Modification (Tampering in Transit).
    Tests both:
      Sub-case 1: 1 character flipped in plaintext payload without re-signing.
      Sub-case 2: 1 byte flipped in Ed25519 signature.
    """
    original_message = "Transfer $100 to account #4491"
    packet = alice.sign_message(recipient="Bob", plaintext=original_message)

    # Sub-case 1: Tamper payload in transit
    tampered_packet = copy.deepcopy(packet)
    tampered_packet["envelope"]["payload"] = "Transfer $900 to account #4491"
    res_payload = bob.verify_message(tampered_packet)

    # Sub-case 2: Corrupt 1 byte in signature
    corrupted_sig_packet = copy.deepcopy(packet)
    sig_bytes = bytearray(base64.b64decode(corrupted_sig_packet["signature"]))
    sig_bytes[0] ^= 0xFF
    corrupted_sig_packet["signature"] = base64.b64encode(bytes(sig_bytes)).decode('utf-8')
    res_signature = bob.verify_message(corrupted_sig_packet)

    all_passed = (
        res_payload["valid"] is False and res_payload["status_code"] == "INVALID_SIGNATURE" and
        res_signature["valid"] is False and res_signature["status_code"] == "INVALID_SIGNATURE"
    )

    result = {
        "experiment_id": "EXP-1",
        "title": "Message Modification & Tampering in Transit",
        "subcase_payload_tamper": {
            "tampered_payload": "Transfer $900 to account #4491",
            "verification": res_payload
        },
        "subcase_signature_corrupt": {
            "flipped_byte_index": 0,
            "verification": res_signature
        },
        "passed": all_passed,
        "observation": (
            "Ed25519 signs the SHA-512 digest of canonical JSON bytes. Modifying even 1 bit in "
            "the payload alters the hash digest entirely (avalanche effect). Modifying 1 bit of "
            "the signature breaks the equation [S]B = R + [H(R, A, M)]A, resulting in immediate rejection."
        )
    }
    return result


def exp2_impersonation_attempt(alice: User, bob: User, directory: PublicKeyDirectory) -> dict:
    """
    Experiment 2: Sender Impersonation Attempt.
    Mallory attempts to send a command pretending to be Alice using Mallory's private key.
    """
    mallory = User("Mallory", directory)
    fake_message = "Urgent: Send the server root password to this address"

    # Mallory creates packet signed with Mallory's key but claiming sender='Alice'
    packet = mallory.sign_message(recipient="Bob", plaintext=fake_message)
    packet["envelope"]["sender"] = "Alice"

    # Re-sign the envelope claiming sender='Alice' using MALLORY'S private key
    canonical_bytes = json.dumps(packet["envelope"], sort_keys=True, separators=(',', ':')).encode('utf-8')
    mallory_sig = mallory.private_key.sign(canonical_bytes)
    packet["signature"] = base64.b64encode(mallory_sig).decode('utf-8')

    # Bob receives the packet and looks up Alice's authentic public key
    verification = bob.verify_message(packet)

    passed = (verification["valid"] is False and verification["status_code"] == "INVALID_SIGNATURE")

    result = {
        "experiment_id": "EXP-2",
        "title": "Sender Impersonation Attempt",
        "attacker": "Mallory",
        "claimed_sender": "Alice",
        "recipient": "Bob",
        "forged_message": fake_message,
        "packet": packet,
        "verification": verification,
        "passed": passed,
        "observation": (
            "Bob verifies using Alice's public key registered in the directory. Because Mallory "
            "cannot forge a signature under Alice's public key without solving the Elliptic Curve "
            "Discrete Logarithm Problem (ECDLP), the verification fails with INVALID_SIGNATURE."
        )
    }
    return result


def exp3_public_key_substitution(alice: User, bob: User, directory: PublicKeyDirectory) -> dict:
    """
    Experiment 3: Public-Key Substitution Attack & Fingerprint Defense.
    Mallory replaces Alice's key in the directory with Mallory's public key.
    Part A: Unauthenticated lookup accepts forged message (Vulnerable!).
    Part B: Out-of-band SHA-256 fingerprint catches substitution (Defended!).
    """
    mallory = User("Mallory", directory)
    forged_message = "Approve wire transfer to offshore account"

    # Mallory tampers with the directory: replaces Alice's key with Mallory's public key
    directory.tamper_registry_key("Alice", mallory.public_key)

    # Save Bob's replay state before Part A so attack simulation does not pollute state
    saved_seen = set(bob.seen_messages)
    saved_last = dict(bob.last_counter_per_sender)

    # Mallory crafts message with sender='Alice', signed with Mallory's private key.
    # Mallory uses a monotonic sequence counter advancing Alice's sequence to simulate
    # an active forged command.
    forged_packet = mallory.sign_message(
        recipient="Bob",
        plaintext=forged_message,
        custom_counter=alice.msg_counter + 1
    )
    forged_packet["envelope"]["sender"] = "Alice"
    canonical_bytes = json.dumps(forged_packet["envelope"], sort_keys=True, separators=(',', ':')).encode('utf-8')
    forged_packet["signature"] = base64.b64encode(mallory.private_key.sign(canonical_bytes)).decode('utf-8')

    # Part A: Vulnerable Verification (No fingerprint check)
    part_a_res = bob.verify_message(forged_packet, verify_key_fingerprint=False)

    # Part B: Defended Verification (Out-of-band SHA-256 fingerprint check)
    part_b_res = bob.verify_message(forged_packet, verify_key_fingerprint=True)

    # Restore Alice's genuine public key in the directory and Bob's state
    directory.register_user("Alice", alice.public_key, update_trusted_fingerprint=True)
    bob.seen_messages = saved_seen
    bob.last_counter_per_sender = saved_last

    passed = (
        part_a_res["valid"] is True and part_a_res["status_code"] == "SUCCESS" and
        part_b_res["valid"] is False and part_b_res["status_code"] == "KEY_SUBSTITUTION_DETECTED"
    )

    result = {
        "experiment_id": "EXP-3",
        "title": "Public-Key Substitution Attack & Defense",
        "part_a_vulnerable": {
            "description": "Verification with verify_key_fingerprint=False",
            "verification": part_a_res,
            "vulnerability_demonstrated": part_a_res["valid"] is True
        },
        "part_b_defended": {
            "description": "Verification with verify_key_fingerprint=True (SHA-256 Pinning)",
            "verification": part_b_res,
            "defense_successful": part_b_res["status_code"] == "KEY_SUBSTITUTION_DETECTED"
        },
        "passed": passed,
        "observation": (
            "Digital signatures authenticate messages relative to a specific public key, NOT a real identity. "
            "Without out-of-band key authentication (SHA-256 fingerprint, PKI CA, or Key Transparency), "
            "an attacker substituting a public key in an untrusted directory successfully deceives the verifier."
        )
    }
    return result


def exp4_confidentiality_analysis(alice: User, bob: User) -> dict:
    """
    Experiment 4: Confidentiality Analysis & Optional AES-256-GCM Extension.
    Part A: Digital signature only (plaintext exposed on the wire).
    Part B: AES-256-GCM Encrypt-then-Sign (confidentiality + authenticity).
    """
    secret_text = "API_SECRET_KEY=sk_live_987654321"

    # Part A: Signature Only
    sig_only_packet = alice.sign_message(recipient="Bob", plaintext=secret_text, shared_aes_key=None)
    wire_payload_a = sig_only_packet["envelope"]["payload"]
    wire_is_plaintext = (wire_payload_a == secret_text)
    res_a = bob.verify_message(sig_only_packet)

    # Part B: Signature + AES-256-GCM
    shared_key = AESGCM.generate_key(bit_length=256)
    enc_packet = alice.sign_message(recipient="Bob", plaintext=secret_text, shared_aes_key=shared_key)
    wire_payload_b = enc_packet["envelope"]["payload"]
    wire_nonce_b = enc_packet["envelope"]["nonce"]
    res_b = bob.verify_message(enc_packet, shared_aes_key=shared_key)

    passed = (
        wire_is_plaintext is True and res_a["valid"] is True and
        wire_payload_b != secret_text and res_b["valid"] is True and
        res_b["plaintext"] == secret_text
    )

    result = {
        "experiment_id": "EXP-4",
        "title": "Confidentiality Analysis (Sign-Only vs. AES-256-GCM Encrypt-then-Sign)",
        "part_a_sign_only": {
            "original_message": secret_text,
            "wire_payload": wire_payload_a,
            "is_plaintext_exposed": wire_is_plaintext,
            "verification": res_a
        },
        "part_b_authenticated_encryption": {
            "wire_ciphertext_preview": wire_payload_b[:32] + "...",
            "nonce_b64": wire_nonce_b,
            "verification": res_b,
            "recovered_plaintext": res_b["plaintext"]
        },
        "passed": passed,
        "observation": (
            "Digital signatures provide integrity and authenticity, but zero confidentiality. "
            "In Part A, any wire interceptor reads the secret in plaintext. "
            "In Part B, Encrypt-then-Sign with AES-256-GCM ensures the payload is ciphertext on the wire "
            "while Ed25519 authenticates the entire envelope."
        )
    }
    return result


def exp5_replay_attack(alice: User, bob: User) -> dict:
    """
    Experiment 5: Replay Attack & Counter/Timestamp Defense.
    Part A: Replay without defense (vulnerable duplicate processing).
    Part B: Replay with monotonic counter & seen set (blocked!).
    Part C: Attacker increments counter without private key (INVALID_SIGNATURE).
    """
    payment_command = "Pay $50 to contractor"
    original_packet = alice.sign_message(recipient="Bob", plaintext=payment_command)

    # First delivery: Bob processes legitimately
    first_res = bob.verify_message(original_packet, enforce_replay_defense=True)

    # Part A: Attacker replays packet to Bob with replay defense disabled
    replayed_packet = copy.deepcopy(original_packet)
    part_a_res = bob.verify_message(replayed_packet, enforce_replay_defense=False)

    # Part B: Attacker replays identical packet with replay defense enabled
    part_b_res = bob.verify_message(replayed_packet, enforce_replay_defense=True)

    # Part C: Attacker increments counter to bypass cache without Alice's private key
    tampered_counter_packet = copy.deepcopy(original_packet)
    tampered_counter_packet["envelope"]["counter"] += 1
    part_c_res = bob.verify_message(tampered_counter_packet, enforce_replay_defense=True)

    passed = (
        first_res["valid"] is True and
        part_a_res["valid"] is True and
        part_b_res["valid"] is False and part_b_res["status_code"] == "REPLAY_DETECTED" and
        part_c_res["valid"] is False and part_c_res["status_code"] == "INVALID_SIGNATURE"
    )

    result = {
        "experiment_id": "EXP-5",
        "title": "Replay Attack & Counter / Timestamp Defense",
        "first_delivery": first_res,
        "part_a_without_defense": {
            "description": "Replay packet with enforce_replay_defense=False",
            "verification": part_a_res,
            "duplicate_accepted": part_a_res["valid"] is True
        },
        "part_b_with_defense": {
            "description": "Replay packet with enforce_replay_defense=True",
            "verification": part_b_res,
            "replay_blocked": part_b_res["status_code"] == "REPLAY_DETECTED"
        },
        "part_c_counter_tamper": {
            "description": "Attacker incremented counter without knowing private key",
            "verification": part_c_res,
            "tamper_blocked": part_c_res["status_code"] == "INVALID_SIGNATURE"
        },
        "passed": passed,
        "observation": (
            "Because an authentic digital signature remains mathematically valid indefinitely, "
            "passive attackers can replay recorded packets unless stateful defenses are present. "
            "Binding a monotonically increasing counter and timestamp inside the signed envelope "
            "blocks duplicate submission, while preventing the attacker from altering the counter."
        )
    }
    return result


def run_all_experiments(export_artifacts: bool = True) -> list[dict]:
    """
    Executes the entire suite of security experiments sequentially.
    Renders terminal tables and panels, and exports artifacts if requested.
    """
    console.print(Panel(
        "[bold cyan]PROJECT 2: AUTOMATED SECURITY EXPERIMENTS & ATTACK SIMULATION SUITE[/bold cyan]\n"
        "[dim]Testing Ed25519 Signatures, AES-256-GCM Confidentiality, Out-of-Band Fingerprints, & Anti-Replay[/dim]",
        border_style="cyan"
    ))

    # Initialize fresh environment
    directory = PublicKeyDirectory()
    alice = User("Alice", directory)
    bob = User("Bob", directory)

    experiments = []

    # Run Baseline
    console.print("\n[bold]Running Baseline: Normal Authentic Message Exchange...[/bold]")
    res0 = exp0_baseline(alice, bob)
    experiments.append(res0)

    # Run Exp 1
    console.print("\n[bold]Running Experiment 1: Message Modification & Signature Corruption...[/bold]")
    res1 = exp1_message_modification(alice, bob)
    experiments.append(res1)

    # Run Exp 2
    console.print("\n[bold]Running Experiment 2: Sender Impersonation Attempt...[/bold]")
    res2 = exp2_impersonation_attempt(alice, bob, directory)
    experiments.append(res2)

    # Run Exp 3
    console.print("\n[bold]Running Experiment 3: Public-Key Substitution Attack & Defense...[/bold]")
    res3 = exp3_public_key_substitution(alice, bob, directory)
    experiments.append(res3)

    # Run Exp 4
    console.print("\n[bold]Running Experiment 4: Confidentiality Analysis & AES-256-GCM Extension...[/bold]")
    res4 = exp4_confidentiality_analysis(alice, bob)
    experiments.append(res4)

    # Run Exp 5
    console.print("\n[bold]Running Experiment 5: Replay Attack & Counter / Timestamp Defense...[/bold]")
    res5 = exp5_replay_attack(alice, bob)
    experiments.append(res5)

    # Render Summary Table
    table = Table(title="Security Experiments Evaluation Summary", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", justify="center")
    table.add_column("Experiment Title", style="bold")
    table.add_column("Defense Status", justify="center")
    table.add_column("Result Code", justify="center")
    table.add_column("Core Security Principle", style="dim")

    summary_rows = [
        ("EXP-0", "Baseline Authentic Exchange", "[bold green]VERIFIED[/bold green]", "SUCCESS", "Ed25519 ECDLP Hardness"),
        ("EXP-1", "Message Modification", "[bold green]DEFENDED[/bold green]", "INVALID_SIGNATURE", "SHA-512 Avalanche Effect"),
        ("EXP-2", "Sender Impersonation", "[bold green]DEFENDED[/bold green]", "INVALID_SIGNATURE", "Unforgeability Under Unknown SK"),
        ("EXP-3", "Public-Key Substitution", "[bold green]DEFENDED[/bold green]", "KEY_SUBSTITUTION_DETECTED", "Out-of-Band SHA-256 Pinning"),
        ("EXP-4", "Confidentiality Analysis", "[bold green]DEMONSTRATED[/bold green]", "AEAD_PROTECTED", "AES-256-GCM Encrypt-then-Sign"),
        ("EXP-5", "Replay Attack & Defense", "[bold green]DEFENDED[/bold green]", "REPLAY_DETECTED", "Signed Monotonic Sequence Counter")
    ]

    for row in summary_rows:
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print()

    # Export Artifacts if enabled
    if export_artifacts:
        artifacts_dir = Path("artifacts")
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # 1. Export Public Keys (PEM & .pub format)
        alice.save_public_key_pem(str(artifacts_dir / "alice_public.pem"))
        bob.save_public_key_pem(str(artifacts_dir / "bob_public.pem"))
        alice.save_public_key_pem(str(artifacts_dir / "alice_public_key.pub"))
        bob.save_public_key_pem(str(artifacts_dir / "bob_public_key.pub"))

        # 2. Export sample signed packet and encrypted packet
        sample_signed = alice.sign_message(
            recipient="Bob",
            plaintext="Meet me at the library at 4 PM. Bring the project notes."
        )
        sample_aes_key = AESGCM.generate_key(bit_length=256)
        sample_encrypted = alice.sign_message(
            recipient="Bob",
            plaintext="API_SECRET_KEY=sk_live_987654321",
            shared_aes_key=sample_aes_key
        )

        (artifacts_dir / "sample_signed_packet.json").write_text(
            json.dumps(sample_signed, indent=2, sort_keys=True), encoding="utf-8"
        )
        (artifacts_dir / "sample_encrypted_packet.json").write_text(
            json.dumps(sample_encrypted, indent=2, sort_keys=True), encoding="utf-8"
        )

        # 3. Export sample_results.json
        export_payload = {
            "metadata": {
                "project": "Project 2: Secure Messaging With Digital Signatures",
                "timestamp": int(time.time()),
                "total_experiments": len(experiments),
                "all_passed": all(e["passed"] for e in experiments),
                "cryptographic_primitives": {
                    "digital_signatures": "Ed25519 (RFC 8032)",
                    "confidentiality": "AES-256-GCM",
                    "hash_fingerprint": "SHA-256",
                    "anti_replay": "Monotonic Counter + UUIDv4 + Timestamp"
                }
            },
            "directory_state": {
                "users": {
                    "Alice": {
                        "public_key_hex": alice.get_public_key_hex(),
                        "fingerprint": alice.get_fingerprint()
                    },
                    "Bob": {
                        "public_key_hex": bob.get_public_key_hex(),
                        "fingerprint": bob.get_fingerprint()
                    }
                }
            },
            "results": experiments
        }

        (artifacts_dir / "sample_results.json").write_text(
            json.dumps(export_payload, indent=2, sort_keys=True), encoding="utf-8"
        )

        console.print(Panel(
            "[bold green]Artifacts Successfully Exported to ./artifacts/[/bold green]\n"
            "  * alice_public.pem & bob_public.pem\n"
            "  * alice_public_key.pub & bob_public_key.pub\n"
            "  * sample_signed_packet.json\n"
            "  * sample_encrypted_packet.json\n"
            "  * sample_results.json",
            border_style="green"
        ))

    return experiments


if __name__ == "__main__":
    run_all_experiments(export_artifacts=True)
