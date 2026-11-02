"""Digital Signature-Based Document Verification System
CLI Application & Workflow Orchestrator.

Run from the repository root:
    python -m src.main --help
    python -m src.main keygen
    python -m src.main sign
    python -m src.main verify
    python -m src.main fingerprint
    python -m src.main all
"""

from __future__ import annotations

import argparse
import getpass
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from src.document_signer import DocumentSigner, SigningError
from src.key_fingerprint import KeyFingerprint
from src.key_manager import (
    InvalidPassphraseError,
    KeyFormatError,
    KeyManagementError,
    KeyManager,
    PassphraseError,
)
from src.signature_verifier import SignatureVerifier


# ---------------------------------------------------------
# Repository default paths
# ---------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent

DEFAULT_PRIVATE_KEY = ROOT_DIR / "private" / "my_private_key.pem"
DEFAULT_PUBLIC_KEY = ROOT_DIR / "artifacts" / "signer_public_key.pem"
DEFAULT_DOCUMENT = ROOT_DIR / "sample_data" / "sample_document.txt"
DEFAULT_SIGNATURE = ROOT_DIR / "artifacts" / "sample_document.sig"


# ---------------------------------------------------------
# Formatting and utility helpers
# ---------------------------------------------------------

def ensure_parent_directory(path: Path) -> None:
    """Create parent directories if they do not exist."""
    path.parent.mkdir(parents=True, exist_ok=True)


def print_heading(title: str) -> None:
    """Display a formatted section heading."""
    print("\n" + "=" * 65)
    print(f" {title}")
    print("=" * 65)


# ---------------------------------------------------------
# 1. Key generation command
# ---------------------------------------------------------

def generate_keys(args: argparse.Namespace) -> bool:
    """Generate an Ed25519 key pair and save both keys."""
    print_heading("ED25519 KEY GENERATION")

    private_path = Path(args.private_key).resolve()
    public_path = Path(args.public_key).resolve()

    force = getattr(args, "force", False)

    # Protect existing keys from accidental overwrite unless force is specified
    if not force and (private_path.exists() or public_path.exists()):
        print("Error: One or both destination key files already exist:")
        if private_path.exists():
            print(f"  - Private key: {private_path}")
        if public_path.exists():
            print(f"  - Public key:  {public_path}")
        print("Use --force (-f) to overwrite or choose different output paths.")
        return False

    # Resolve passphrase
    password: Optional[str] = getattr(args, "password", None)
    no_password: bool = getattr(args, "no_password", False)

    if not no_password and password is None:
        if sys.stdin.isatty():
            try:
                entered = getpass.getpass("Enter passphrase to encrypt private key (press Enter for none): ")
                if entered:
                    confirmation = getpass.getpass("Confirm passphrase: ")
                    if entered != confirmation:
                        print("Error: Passphrases do not match.")
                        return False
                    password = entered
                else:
                    password = None
            except (EOFError, KeyboardInterrupt):
                print("\nOperation cancelled.")
                return False
        else:
            password = None

    ensure_parent_directory(private_path)
    ensure_parent_directory(public_path)

    try:
        private_key, public_key = KeyManager.generate_key_pair()

        KeyManager.save_private_key(private_key, private_path, password=password)
        KeyManager.save_public_key(public_key, public_path)

        print("\nKey pair generated successfully.")
        print(f"  Private key: {private_path} {'[ENCRYPTED]' if password else '[UNENCRYPTED]'}")
        print(f"  Public key:  {public_path}")
        print("\nSecurity notice: Keep private keys confidential. Never commit them to git.")
        return True

    except Exception as e:
        print(f"Error generating keys: {e}")
        return False


# ---------------------------------------------------------
# 2. Document signing command
# ---------------------------------------------------------

def sign_document(args: argparse.Namespace) -> bool:
    """Create a detached Ed25519 signature for a document."""
    print_heading("DOCUMENT SIGNING")

    document_path = Path(args.document).resolve()
    private_path = Path(args.private_key).resolve()
    signature_path = Path(args.signature).resolve()

    if not document_path.is_file():
        print(f"Error: Document file not found: {document_path}")
        return False

    if not private_path.is_file():
        print(f"Error: Private key file not found: {private_path}")
        print("Generate a key pair first using 'python -m src.main keygen'.")
        return False

    ensure_parent_directory(signature_path)

    # Resolve passphrase
    password: Optional[str] = getattr(args, "password", None)
    if password is None and sys.stdin.isatty():
        try:
            entered = getpass.getpass("Enter private key passphrase (press Enter if unencrypted): ")
            password = entered if entered else None
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return False

    print(f"Document:    {document_path}")
    print(f"Private key: {private_path}")
    print(f"Signature:   {signature_path}")

    try:
        signature = DocumentSigner.sign_document(
            document_path=document_path,
            private_key=private_path,
            signature_output_path=signature_path,
            password=password,
        )

        if not signature_path.is_file():
            print("Error: Signature output was not written.")
            return False

        sig_size = signature_path.stat().st_size
        if sig_size != 64 or len(signature) != 64:
            print(f"Error: Unexpected signature size ({sig_size} bytes; expected 64 bytes).")
            return False

        print("\nDocument signed successfully.")
        print(f"Detached signature: {signature_path}")
        print(f"Signature size:     {sig_size} bytes (Ed25519 standard)")
        return True

    except InvalidPassphraseError:
        print("Error: Incorrect passphrase provided for private key.")
        return False
    except PassphraseError as e:
        print(f"Error: Private key requires a passphrase: {e}")
        return False
    except (SigningError, KeyManagementError, OSError) as e:
        print(f"Error during signing: {e}")
        return False


# ---------------------------------------------------------
# 3. Document signature verification command
# ---------------------------------------------------------

def verify_document(args: argparse.Namespace) -> bool:
    """Verify a document using its detached signature and public key."""
    print_heading("DOCUMENT SIGNATURE VERIFICATION")

    document_path = Path(args.document).resolve()
    signature_path = Path(args.signature).resolve()
    public_path = Path(args.public_key).resolve()

    print(f"Document:   {document_path}")
    print(f"Signature:  {signature_path}")
    print(f"Public key: {public_path}")

    for label, p in (("Document", document_path), ("Signature", signature_path), ("Public key", public_path)):
        if not p.is_file():
            print(f"\nError: {label} file does not exist: {p}")
            return False

    result = SignatureVerifier.verify_document(
        document_path=document_path,
        signature_source=signature_path,
        public_key_source=public_path,
    )

    print("\nVerification Result:")
    print("-" * 35)
    if result.is_valid:
        print("STATUS:  AUTHENTIC (VALID)")
        print(f"Message: {result.message}")
        if result.details:
            print(f"Details: {result.details}")
        return True
    else:
        print("STATUS:  NOT AUTHENTIC (INVALID)")
        print(f"Message: {result.message}")
        if result.details:
            print(f"Details: {result.details}")
        return False


# ---------------------------------------------------------
# 4. Public-key fingerprint command
# ---------------------------------------------------------

def show_fingerprint(args: argparse.Namespace) -> bool:
    """Compute and display or verify the public key SHA-256 fingerprint."""
    print_heading("PUBLIC KEY FINGERPRINT")

    public_path = Path(args.public_key).resolve()

    if not public_path.is_file():
        print(f"Error: Public key file not found: {public_path}")
        return False

    try:
        fingerprint = KeyFingerprint.compute_fingerprint(public_path)
    except Exception as e:
        print(f"Error computing fingerprint: {e}")
        return False

    print(f"Public key: {public_path}")
    print(f"SHA-256 fingerprint:\n  {fingerprint}")

    expected: Optional[str] = getattr(args, "expected", None)
    if expected:
        matches = KeyFingerprint.verify_fingerprint(public_path, expected)
        print("-" * 35)
        if matches:
            print("[TRUSTED] Fingerprint MATCHES the trusted out-of-band reference.")
            return True
        else:
            print("[UNTRUSTED] Fingerprint DOES NOT MATCH expected reference!")
            print(f"  Expected: {expected}")
            return False

    print("\nTrust validation: Compare this fingerprint against an authenticated reference")
    print("obtained through an out-of-band channel to prevent key substitution attacks.")
    return True


# ---------------------------------------------------------
# 5. Complete end-to-end workflow command
# ---------------------------------------------------------

def run_all(args: argparse.Namespace) -> bool:
    """Run the complete digital signature demonstration workflow."""
    print_heading("DIGITAL SIGNATURE VERIFICATION WORKFLOW")

    # Step 1: Verify the repository's official submission artifacts
    print("\n--- PHASE 1: Auditing Repository Submission Artifacts ---")
    if DEFAULT_DOCUMENT.is_file() and DEFAULT_SIGNATURE.is_file() and DEFAULT_PUBLIC_KEY.is_file():
        print(f"Checking official sample document: {DEFAULT_DOCUMENT.name}")
        audit_args = argparse.Namespace(
            document=str(DEFAULT_DOCUMENT),
            signature=str(DEFAULT_SIGNATURE),
            public_key=str(DEFAULT_PUBLIC_KEY),
        )
        sample_ok = verify_document(audit_args)
        if not sample_ok:
            print("Warning: Repository sample artifacts failed verification.")
            return False

        fp_args = argparse.Namespace(public_key=str(DEFAULT_PUBLIC_KEY), expected=None)
        show_fingerprint(fp_args)
    else:
        print("Note: Sample artifacts not fully present in expected default paths.")

    # Step 2: Demonstrate dynamic end-to-end signing and verification lifecycle
    print("\n--- PHASE 2: Live End-to-End Cryptographic Lifecycle ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        demo_priv = tmp_path / "demo_private.pem"
        demo_pub = tmp_path / "demo_public.pem"
        demo_doc = tmp_path / "demo_document.txt"
        demo_sig = tmp_path / "demo_signature.sig"

        demo_doc.write_bytes(
            b"Official University Degree - Candidate: Aryan - Specialization: Cryptography\n"
        )

        # 1. Key Generation
        kg_args = argparse.Namespace(
            private_key=str(demo_priv),
            public_key=str(demo_pub),
            password="DemoPassphrase2026!",
            no_password=False,
            force=True,
        )
        if not generate_keys(kg_args):
            print("Workflow error: Demo key generation failed.")
            return False

        # 2. Document Signing
        sig_args = argparse.Namespace(
            document=str(demo_doc),
            private_key=str(demo_priv),
            signature=str(demo_sig),
            password="DemoPassphrase2026!",
        )
        if not sign_document(sig_args):
            print("Workflow error: Demo document signing failed.")
            return False

        # 3. Signature Verification
        v_args = argparse.Namespace(
            document=str(demo_doc),
            signature=str(demo_sig),
            public_key=str(demo_pub),
        )
        if not verify_document(v_args):
            print("Workflow error: Demo verification failed.")
            return False

        # 4. Fingerprint Calculation & Out-of-band trust match
        demo_fp = KeyFingerprint.compute_fingerprint(demo_pub)
        fp_args = argparse.Namespace(public_key=str(demo_pub), expected=demo_fp)
        if not show_fingerprint(fp_args):
            print("Workflow error: Demo fingerprint verification failed.")
            return False

        # 5. Tamper Detection Proof
        print("\n--- PHASE 3: Tamper Detection Demonstration ---")
        tampered_doc = tmp_path / "tampered.txt"
        tampered_doc.write_bytes(demo_doc.read_bytes() + b"[TAMPERED DATA]")

        tamper_args = argparse.Namespace(
            document=str(tampered_doc),
            signature=str(demo_sig),
            public_key=str(demo_pub),
        )
        tamper_res = SignatureVerifier.verify_document(
            document_path=tampered_doc,
            signature_source=demo_sig,
            public_key_source=demo_pub,
        )
        if not tamper_res.is_valid:
            print("[PASS] Tampered document was successfully detected and rejected!")
            print(f"       Message: {tamper_res.message}")
        else:
            print("[FAIL] Tampered document was incorrectly accepted!")
            return False

    print_heading("ALL WORKFLOW STAGES COMPLETED SUCCESSFULLY")
    print(" 1. Key Pair Generation: Verified")
    print(" 2. Detached Document Signing: Verified (64 bytes)")
    print(" 3. Cryptographic Verification: Verified")
    print(" 4. Public-Key Fingerprint Validation: Verified")
    print(" 5. Tamper Resistance: Verified")
    return True


# ---------------------------------------------------------
# 6. Command-line argument parser
# ---------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Ed25519-based document signing, verification and public-key fingerprint utility.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Key generation parser
    keygen_parser = subparsers.add_parser("keygen", help="Generate an Ed25519 key pair.")
    keygen_parser.add_argument(
        "--private-key",
        default=str(DEFAULT_PRIVATE_KEY),
        help=f"Output path for the private key PEM (default: {DEFAULT_PRIVATE_KEY})",
    )
    keygen_parser.add_argument(
        "--public-key",
        default=str(DEFAULT_PUBLIC_KEY),
        help=f"Output path for the public key PEM (default: {DEFAULT_PUBLIC_KEY})",
    )
    keygen_parser.add_argument(
        "--password",
        default=None,
        help="Passphrase to encrypt the private key at rest (prompted interactively if omitted)",
    )
    keygen_parser.add_argument(
        "--no-password",
        action="store_true",
        help="Store private key unencrypted without prompting for a passphrase",
    )
    keygen_parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Overwrite existing key files if they exist",
    )
    keygen_parser.set_defaults(func=generate_keys)

    # Document signing parser
    sign_parser = subparsers.add_parser("sign", help="Sign a document and create a detached signature.")
    sign_parser.add_argument(
        "--document",
        default=str(DEFAULT_DOCUMENT),
        help=f"Path to the document to sign (default: {DEFAULT_DOCUMENT})",
    )
    sign_parser.add_argument(
        "--private-key",
        default=str(DEFAULT_PRIVATE_KEY),
        help=f"Path to the private key PEM (default: {DEFAULT_PRIVATE_KEY})",
    )
    sign_parser.add_argument(
        "--signature",
        default=str(DEFAULT_SIGNATURE),
        help=f"Output path for the detached signature (default: {DEFAULT_SIGNATURE})",
    )
    sign_parser.add_argument(
        "--password",
        default=None,
        help="Passphrase for encrypted private key (prompted interactively if omitted)",
    )
    sign_parser.set_defaults(func=sign_document)

    # Signature verification parser
    verify_parser = subparsers.add_parser("verify", help="Verify a document's detached signature.")
    verify_parser.add_argument(
        "--document",
        default=str(DEFAULT_DOCUMENT),
        help=f"Path to the document file (default: {DEFAULT_DOCUMENT})",
    )
    verify_parser.add_argument(
        "--signature",
        default=str(DEFAULT_SIGNATURE),
        help=f"Path to the detached signature file (default: {DEFAULT_SIGNATURE})",
    )
    verify_parser.add_argument(
        "--public-key",
        default=str(DEFAULT_PUBLIC_KEY),
        help=f"Path to the signer's public key PEM (default: {DEFAULT_PUBLIC_KEY})",
    )
    verify_parser.set_defaults(func=verify_document)

    # Fingerprint parser
    fingerprint_parser = subparsers.add_parser("fingerprint", help="Compute or verify a public-key SHA-256 fingerprint.")
    fingerprint_parser.add_argument(
        "--public-key",
        default=str(DEFAULT_PUBLIC_KEY),
        help=f"Path to the public key PEM (default: {DEFAULT_PUBLIC_KEY})",
    )
    fingerprint_parser.add_argument(
        "--expected",
        default=None,
        help="Expected trusted fingerprint to verify against (e.g. 'SHA256:56:fe:...')",
    )
    fingerprint_parser.set_defaults(func=show_fingerprint)

    # Full workflow parser
    all_parser = subparsers.add_parser("all", help="Run the complete digital signature demonstration workflow.")
    all_parser.set_defaults(func=run_all)

    return parser


# ---------------------------------------------------------
# 7. Application entry point
# ---------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI application main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        success = args.func(args)
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        return 130
    except Exception as exc:
        print(f"\nOperation failed unexpectedly: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
