import argparse
import sys
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

def generate_keys():
    """Generates an Ed25519 private and public key pair and saves them to PEM files."""
    if os.path.exists("private_key.pem") or os.path.exists("public_key.pem"):
        print("[-] Error: Key files already exist! Delete them first if you want to regenerate.")
        sys.exit(1)

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    os.chmod("private_key.pem", 0o600)

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("[+] Keys generated successfully: 'private_key.pem' and 'public_key.pem'")

def sign_document(doc_path, sig_path):
    """Signs a document using the private key and saves the signature."""
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except (ValueError, UnsupportedAlgorithm, Exception):
        print("[-] Error: The private key file is corrupted, malformed, or tampered with.")
        sys.exit(1)

    try:
        with open(doc_path, "rb") as f:
            document_data = f.read()

        signature = private_key.sign(document_data)

        with open(sig_path, "wb") as f:
            f.write(signature)
            
        print(f"[+] Document '{doc_path}' signed successfully. Signature saved to '{sig_path}'.")
    except FileNotFoundError:
        print(f"[-] Error: Target document '{doc_path}' not found.")
        sys.exit(1)

def verify_document(doc_path, sig_path):
    """Verifies a document's signature against the public key[cite: 5]."""
    try:
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    except (ValueError, UnsupportedAlgorithm, Exception):
        print("[-] Error: The public key file is corrupted, malformed, or tampered with.")
        sys.exit(1)
            
    try:
        with open(doc_path, "rb") as f:
            document_data = f.read()
            
        with open(sig_path, "rb") as f:
            signature = f.read()

        public_key.verify(signature, document_data)
        print("[SUCCESS] Signature is VALID. The document has not been tampered with.")
    except InvalidSignature:
        print("[FAILURE] Signature is INVALID. The document has been modified or the signature is wrong.")
    except FileNotFoundError:
        print("[-] Error: Missing document or signature file.")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Document Verification Tool using Ed25519")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for generating keys
    subparsers.add_parser("generate-keys", help="Generate Ed25519 key pair")

    # Subparser for signing
    parser_sign = subparsers.add_parser("sign", help="Sign a document")
    parser_sign.add_argument("doc", help="Path to the document to sign")
    parser_sign.add_argument("sig", help="Path to save the output signature file")

    # Subparser for verifying
    parser_verify = subparsers.add_parser("verify", help="Verify a document signature")
    parser_verify.add_argument("doc", help="Path to the document to verify")
    parser_verify.add_argument("sig", help="Path to the signature file")

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys()
    elif args.command == "sign":
        sign_document(args.doc, args.sig)
    elif args.command == "verify":
        verify_document(args.doc, args.sig)
        