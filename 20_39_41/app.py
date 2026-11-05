#!/usr/bin/env python3
"""
Project 2: Secure Messaging With Digital Signatures
Member 3 Deliverable: Interactive CLI Application (app.py)
"""

import argparse
import base64
import copy
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table

# Import Member 1 and Member 2 modules per Dependency Contract
from crypto_core import PublicKeyDirectory, SecurityError, User
from experiments import (
    exp0_baseline,
    exp1_message_modification,
    exp2_impersonation_attempt,
    exp3_public_key_substitution,
    exp4_confidentiality_analysis,
    exp5_replay_attack,
    run_all_experiments,
)

console = Console()


class InteractiveMessagingSimulator:
    """Interactive CLI Simulator for Digital Signatures & Attack Sandbox."""

    def __init__(self) -> None:
        self.directory = PublicKeyDirectory()
        self.alice = User("Alice", self.directory)
        self.bob = User("Bob", self.directory)
        self.mallory = User("Mallory", self.directory)
        self.users: dict[str, User] = {
            "Alice": self.alice,
            "Bob": self.bob,
            "Mallory": self.mallory,
        }
        self.shared_aes_key: bytes = AESGCM.generate_key(bit_length=256)
        self.last_packet: dict | None = None
        self.last_used_aes: bool = False

    def display_banner(self) -> None:
        banner_text = (
            "[bold cyan]Project 2: Secure Messaging With Digital Signatures[/bold cyan]\n"
            "[dim]Primitives: Ed25519 (RFC 8032) | Optional AEAD: AES-256-GCM | Directory: SHA-256 Out-of-Band Fingerprints[/dim]"
        )
        console.print(Panel(banner_text, border_style="cyan", expand=False))

    def view_key_directory(self) -> None:
        """Option [1]: View Key Directory & Trusted Fingerprints."""
        table = Table(
            title="Public Key Directory & Out-of-Band Trusted Fingerprints",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("User", style="bold cyan", width=10)
        table.add_column("Registered Ed25519 Public Key (32-Byte Hex)", style="green")
        table.add_column("Trusted Out-of-Band SHA-256 Fingerprint", style="yellow")
        table.add_column("Integrity Status", justify="center")

        for username in ["Alice", "Bob", "Mallory"]:
            reg_pub_hex = self.directory.get_public_key_hex(username)
            trusted_fp = self.directory.trusted_fingerprints.get(username, "N/A")

            try:
                self.directory.get_public_key(username, verify_fingerprint=True)
                status = "[bold green]AUTHENTIC[/bold green]"
            except SecurityError:
                status = "[bold red]TAMPERED / SUBSTITUTED[/bold red]"

            table.add_row(username, reg_pub_hex, trusted_fp, status)

        console.print()
        console.print(table)
        console.print()

    def _print_wire_packet(self, packet: dict, title: str = "Network Wire: Transmitted JSON Packet") -> None:
        json_str = json.dumps(packet, indent=2, sort_keys=True)
        syntax = Syntax(json_str, "json", theme="monokai", word_wrap=True)
        console.print(Panel(syntax, title=f"[bold yellow]{title}[/bold yellow]", border_style="yellow"))

    def _print_verification_result(self, result: dict, title: str = "Recipient Verification Result") -> None:
        is_valid = result.get("valid", False)
        border_color = "green" if is_valid else "red"
        status_badge = (
            f"[bold green]VALID ({result.get('status_code')})[/bold green]"
            if is_valid
            else f"[bold red]REJECTED ({result.get('status_code')})[/bold red]"
        )

        details = (
            f"[bold]Verification Verdict:[/bold] {status_badge}\n"
            f"[bold]Claimed Sender:[/bold]       {result.get('sender')}\n"
            f"[bold]Claimed Recipient:[/bold]    {result.get('recipient')}\n"
            f"[bold]Reason / Diagnostic:[/bold]  {result.get('reason')}\n"
            f"[bold]AES-GCM Encrypted:[/bold]    {result.get('encrypted')}\n"
            f"[bold]Message Counter:[/bold]      {result.get('counter')}\n"
            f"[bold]UTC Timestamp:[/bold]        {result.get('timestamp')}\n"
            f"[bold]Signature Preview:[/bold]    {result.get('signature_hex_preview')}...\n"
            f"[bold]Recovered Plaintext:[/bold]  [bold cyan]{result.get('plaintext')}[/bold cyan]"
        )
        console.print(Panel(details, title=f"[bold {border_color}]{title}[/bold {border_color}]", border_style=border_color))

    def send_signed_message(self) -> None:
        """Option [2]: Send Signed Message (Alice <-> Bob)."""
        console.print("\n[bold cyan]--- Send Signed Message (Alice <-> Bob) ---[/bold cyan]")
        sender_name = Prompt.ask("Select Sender", choices=["Alice", "Bob"], default="Alice")
        default_recipient = "Bob" if sender_name == "Alice" else "Alice"
        recipient_name = Prompt.ask("Select Recipient", choices=["Alice", "Bob"], default=default_recipient)
        plaintext = Prompt.ask(
            "Enter message text",
            default="Transfer $500 to project escrow account #8821.",
        )
        use_aes = Confirm.ask("Enable Optional AES-256-GCM Confidentiality Extension?", default=False)

        sender = self.users[sender_name]
        recipient = self.users[recipient_name]
        aes_key = self.shared_aes_key if use_aes else None

        packet = sender.sign_message(
            recipient=recipient_name,
            plaintext=plaintext,
            shared_aes_key=aes_key,
        )

        self.last_packet = copy.deepcopy(packet)
        self.last_used_aes = use_aes

        console.print()
        self._print_wire_packet(packet)

        result = recipient.verify_message(
            packet=packet,
            enforce_replay_defense=True,
            verify_key_fingerprint=True,
            shared_aes_key=aes_key,
        )
        self._print_verification_result(result, title=f"{recipient_name}'s Verification Result")

    def attacker_sandbox(self) -> None:
        """Option [3]: Interactive Attacker Sandbox (Tamper / Impersonate / Substitute Key / Replay)."""
        console.print("\n[bold red]--- Interactive Attacker Sandbox (Active MITM: Mallory) ---[/bold red]")
        console.print(
            "  [bold]3a[/bold] - Modify Message Payload in Transit (without re-signing)\n"
            "  [bold]3b[/bold] - Corrupt Ed25519 Signature Bytes (1-byte bit flip)\n"
            "  [bold]3c[/bold] - Impersonate Sender (Sign with Mallory's private key claiming 'Alice')\n"
            "  [bold]3d[/bold] - Public-Key Substitution (Swap Alice's key in directory + toggle Fingerprint Defense)\n"
            "  [bold]3e[/bold] - Replay Captured Packet (Resend exact packet + toggle Replay Defense)\n"
            "  [bold]b[/bold]  - Back to Main Menu"
        )

        sub_choice = Prompt.ask(
            "Choose an attack scenario",
            choices=["3a", "3b", "3c", "3d", "3e", "b"],
            default="3a",
        )
        if sub_choice == "b":
            return

        if sub_choice in ("3a", "3b", "3e") and self.last_packet is None:
            console.print(
                "[yellow]No recent message found in session buffer. Generating a baseline signed packet from Alice -> Bob first...[/yellow]"
            )
            self.last_packet = self.alice.sign_message(
                recipient="Bob",
                plaintext="Authorize payment of $100 to vendor.",
                shared_aes_key=None,
            )
            self.last_used_aes = False
            self.bob.verify_message(
                self.last_packet,
                enforce_replay_defense=True,
                verify_key_fingerprint=True,
            )

        if sub_choice == "3a":
            self._attack_3a_modify_payload()
        elif sub_choice == "3b":
            self._attack_3b_corrupt_signature()
        elif sub_choice == "3c":
            self._attack_3c_impersonate_sender()
        elif sub_choice == "3d":
            self._attack_3d_public_key_substitution()
        elif sub_choice == "3e":
            self._attack_3e_replay_packet()

    def _attack_3a_modify_payload(self) -> None:
        tampered_packet = copy.deepcopy(self.last_packet)
        orig_payload = tampered_packet["envelope"]["payload"]
        console.print(f"[dim]Original Envelope Payload:[/dim] {orig_payload}")

        fake_payload = Prompt.ask(
            "Enter Mallory's modified payload text (injected without re-signing)",
            default="Authorize payment of $999,999 to Mallory.",
        )
        tampered_packet["envelope"]["payload"] = fake_payload

        self._print_wire_packet(tampered_packet, title="MITM Wire: Tampered Payload Packet")

        recipient_name = tampered_packet["envelope"].get("recipient", "Bob")
        recipient = self.users.get(recipient_name, self.bob)
        aes_key = self.shared_aes_key if self.last_used_aes else None

        result = recipient.verify_message(
            tampered_packet,
            enforce_replay_defense=True,
            verify_key_fingerprint=True,
            shared_aes_key=aes_key,
        )
        self._print_verification_result(result, title=f"{recipient_name}'s Verification of Tampered Payload")

    def _attack_3b_corrupt_signature(self) -> None:
        corrupted_packet = copy.deepcopy(self.last_packet)
        sig_bytes = bytearray(base64.b64decode(corrupted_packet["signature"]))
        sig_bytes[0] ^= 0xFF
        corrupted_packet["signature"] = base64.b64encode(bytes(sig_bytes)).decode("utf-8")

        console.print("[yellow]Mallory flipped 1 byte (XOR 0xFF at index 0) of the 64-byte Ed25519 signature.[/yellow]")
        self._print_wire_packet(corrupted_packet, title="MITM Wire: Corrupted Signature Packet")

        recipient_name = corrupted_packet["envelope"].get("recipient", "Bob")
        recipient = self.users.get(recipient_name, self.bob)
        aes_key = self.shared_aes_key if self.last_used_aes else None

        result = recipient.verify_message(
            corrupted_packet,
            enforce_replay_defense=True,
            verify_key_fingerprint=True,
            shared_aes_key=aes_key,
        )
        self._print_verification_result(result, title=f"{recipient_name}'s Verification of Corrupted Signature")

    def _attack_3c_impersonate_sender(self) -> None:
        fake_text = Prompt.ask(
            "Enter message Mallory wants to forge as 'Alice'",
            default="Urgent: Send the production SSH private key to this address.",
        )

        forged_packet = self.mallory.sign_message(recipient="Bob", plaintext=fake_text)
        forged_packet["envelope"]["sender"] = "Alice"
        canonical_bytes = json.dumps(
            forged_packet["envelope"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        mallory_sig = self.mallory.private_key.sign(canonical_bytes)
        forged_packet["signature"] = base64.b64encode(mallory_sig).decode("utf-8")

        console.print(
            "[yellow]Mallory signed the canonical envelope with Mallory's private key, but set envelope['sender'] = 'Alice'.[/yellow]"
        )
        self._print_wire_packet(forged_packet, title="MITM Wire: Impersonation Packet (Signed by Mallory)")

        result = self.bob.verify_message(
            forged_packet,
            enforce_replay_defense=True,
            verify_key_fingerprint=True,
        )
        self._print_verification_result(result, title="Bob's Verification (Using Alice's Authentic Public Key)")

    def _attack_3d_public_key_substitution(self) -> None:
        forged_text = Prompt.ask(
            "Enter message Mallory signs after substituting Alice's public key in the directory",
            default="Approve wire transfer of $250,000 to offshore account.",
        )
        verify_fp = Confirm.ask(
            "Enable Out-of-Band SHA-256 Fingerprint Defense on Bob's client?",
            default=True,
        )

        self.directory.tamper_registry_key("Alice", self.mallory.public_key)
        console.print(
            "[bold red]! Directory Compromised:[/bold red] Alice's entry in PublicKeyDirectory replaced with Mallory's public key."
        )

        try:
            forged_packet = self.mallory.sign_message(recipient="Bob", plaintext=forged_text)
            forged_packet["envelope"]["sender"] = "Alice"
            forged_packet["envelope"]["counter"] = self.alice.msg_counter + 500
            canonical_bytes = json.dumps(
                forged_packet["envelope"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            mallory_sig = self.mallory.private_key.sign(canonical_bytes)
            forged_packet["signature"] = base64.b64encode(mallory_sig).decode("utf-8")

            self._print_wire_packet(forged_packet, title="MITM Wire: Key-Substitution Forged Packet")

            result = self.bob.verify_message(
                forged_packet,
                enforce_replay_defense=False,
                verify_key_fingerprint=verify_fp,
            )
            self._print_verification_result(
                result,
                title=f"Bob's Verification (verify_key_fingerprint={verify_fp})",
            )
        finally:
            self.directory.register_user("Alice", self.alice.public_key, update_trusted_fingerprint=True)
            console.print("[dim green]✓ Restored Alice's authentic public key in PublicKeyDirectory.[/dim green]")

    def _attack_3e_replay_packet(self) -> None:
        enforce_replay = Confirm.ask(
            "Enable Replay Defense (Sequence Counter & Timestamp tracking) on Recipient?",
            default=True,
        )

        replayed_packet = copy.deepcopy(self.last_packet)
        recipient_name = replayed_packet["envelope"].get("recipient", "Bob")
        recipient = self.users.get(recipient_name, self.bob)
        aes_key = self.shared_aes_key if self.last_used_aes else None

        console.print(
            f"[yellow]Mallory is re-transmitting captured packet (msg_id={replayed_packet['envelope'].get('msg_id')}, "
            f"counter={replayed_packet['envelope'].get('counter')}) to {recipient_name}.[/yellow]"
        )
        self._print_wire_packet(replayed_packet, title="MITM Wire: Replayed Packet")

        result = recipient.verify_message(
            replayed_packet,
            enforce_replay_defense=enforce_replay,
            verify_key_fingerprint=True,
            shared_aes_key=aes_key,
        )
        self._print_verification_result(
            result,
            title=f"{recipient_name}'s Verification (enforce_replay_defense={enforce_replay})",
        )

    def ensure_repo_artifacts(self) -> None:
        """Ensures both spec artifacts and git-tree artifacts exist in artifacts/."""
        artifacts_dir = Path("artifacts")
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Save .pub files (tracked in Git since *.pem is gitignored) and .pem files (for spec compliance)
        self.alice.save_public_key_pem(str(artifacts_dir / "alice_public_key.pub"))
        self.bob.save_public_key_pem(str(artifacts_dir / "bob_public_key.pub"))
        self.alice.save_public_key_pem(str(artifacts_dir / "alice_public.pem"))
        self.bob.save_public_key_pem(str(artifacts_dir / "bob_public.pem"))

        # Generate sample_signed_packet.json and sample_encrypted_packet.json
        signed_sample = self.alice.sign_message(
            recipient="Bob",
            plaintext="Meet me at the library at 4 PM. Bring the project notes.",
            shared_aes_key=None,
        )
        encrypted_sample = self.alice.sign_message(
            recipient="Bob",
            plaintext="API_SECRET_KEY=sk_live_987654321",
            shared_aes_key=self.shared_aes_key,
        )

        (artifacts_dir / "sample_signed_packet.json").write_text(
            json.dumps(signed_sample, indent=2, sort_keys=True), encoding="utf-8"
        )
        (artifacts_dir / "sample_encrypted_packet.json").write_text(
            json.dumps(encrypted_sample, indent=2, sort_keys=True), encoding="utf-8"
        )

    def run_automated_experiments(self) -> None:
        """Option [4]: Run All 5 Automated Rubric Security Experiments."""
        console.print("\n[bold cyan]--- Running All Automated Rubric Security Experiments ---[/bold cyan]")
        run_all_experiments(export_artifacts=True)
        self.ensure_repo_artifacts()

        artifacts_dir = Path("artifacts")
        expected_files = [
            artifacts_dir / "sample_signed_packet.json",
            artifacts_dir / "sample_encrypted_packet.json",
            artifacts_dir / "alice_public_key.pub",
            artifacts_dir / "bob_public_key.pub",
            artifacts_dir / "sample_results.json",
        ]

        confirm_table = Table(title="Generated Artifact Verification", show_header=True, header_style="bold green")
        confirm_table.add_column("Artifact File Path", style="cyan")
        confirm_table.add_column("Status", justify="center")
        confirm_table.add_column("Size (Bytes)", justify="right")

        for filepath in expected_files:
            if filepath.exists():
                confirm_table.add_row(str(filepath), "[bold green]SAVED[/bold green]", str(filepath.stat().st_size))
            else:
                confirm_table.add_row(str(filepath), "[bold red]MISSING[/bold red]", "0")

        console.print()
        console.print(confirm_table)
        console.print()

    def run_loop(self) -> None:
        self.display_banner()
        while True:
            try:
                console.print("[bold]Interactive Menu Options:[/bold]")
                console.print("  [bold cyan][1][/bold cyan] View Key Directory & Trusted Fingerprints")
                console.print("  [bold cyan][2][/bold cyan] Send Signed Message (Alice <-> Bob)")
                console.print(
                    "  [bold cyan][3][/bold cyan] Interactive Attacker Sandbox (Tamper / Impersonate / Substitute Key / Replay)"
                )
                console.print("  [bold cyan][4][/bold cyan] Run All 5 Automated Rubric Security Experiments")
                console.print("  [bold cyan][5][/bold cyan] Exit")

                choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"], default="1")

                if choice == "1":
                    self.view_key_directory()
                elif choice == "2":
                    self.send_signed_message()
                elif choice == "3":
                    self.attacker_sandbox()
                elif choice == "4":
                    self.run_automated_experiments()
                elif choice == "5":
                    console.print("[bold green]Exiting simulator. Stay secure![/bold green]")
                    break
            except (KeyboardInterrupt, EOFError):
                console.print("\n[bold yellow]Session interrupted by user. Exiting cleanly...[/bold yellow]")
                break
            except Exception as exc:
                console.print(f"[bold red]Unexpected error caught safely:[/bold red] {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Project 2: Secure Messaging With Digital Signatures — Interactive Simulator & Test Runner"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run all automated security experiments non-interactively and exit with code 0.",
    )
    parser.add_argument(
        "--experiments",
        action="store_true",
        help="Alias for --test: run all automated security experiments and export artifacts.",
    )
    args = parser.parse_args()

    simulator = InteractiveMessagingSimulator()
    if args.test or args.experiments:
        run_all_experiments(export_artifacts=True)
        simulator.ensure_repo_artifacts()
        return 0

    simulator.run_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())