"""
main.py - command-line interface for Ed25519 document signing and verification.

Commands:
  keygen              generate a key pair
  sign                sign a document (detached signature)
  verify              verify document + signature + public key
  fingerprint         print a public key's SHA-256 fingerprint
  experiments         run Experiments 1-4 on temporary copies
  demo-substitution   run Experiment 5 (public-key substitution)

Exit codes: 0 = verified / success, 1 = verification failed, 2 = input error.
"""
import argparse
import hashlib
import sys
import tempfile
from pathlib import Path

import crypto_utils as cu

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_PRIVATE = Path.home() / ".dsig_keys" / "private_key.pem"   # outside project
DEFAULT_PUBLIC = PROJECT_DIR / "artifacts" / "public_key.pem"
DEFAULT_SIGNATURE = PROJECT_DIR / "artifacts" / "signature.bin"
DEFAULT_DOCUMENT = PROJECT_DIR / "sample_document.txt"


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def show(result):
    """Print a verification result; return the matching exit code."""
    if result.ok:
        print(f"[VERIFIED] {result.reason}")
        return 0
    print(f"[FAILED]   {result.reason}")
    return 1


# ------------------------------------------------------------------ commands
def cmd_keygen(args):
    fp = cu.generate_keypair(args.private_key, args.public_key, overwrite=args.force)
    print(f"Private key saved to: {args.private_key}  (keep secret, never submit)")
    print(f"Public key saved to:  {args.public_key}")
    print(f"Public-key fingerprint (SHA-256): {fp}")
    return 0


def cmd_sign(args):
    out = cu.sign_file(args.document, args.private_key, args.output)
    print(f"Signed:    {args.document}  (document not modified)")
    print(f"Signature: {out}  ({cu.SIGNATURE_LENGTH} bytes)")
    return 0


def cmd_verify(args):
    if args.trusted_fingerprint:
        result = cu.verify_with_trusted_fingerprint(
            args.document, args.signature, args.public_key, args.trusted_fingerprint)
    else:
        result = cu.verify_file(args.document, args.signature, args.public_key)
    return show(result)


def cmd_fingerprint(args):
    print(cu.fingerprint(args.public_key))
    return 0


def cmd_experiments(args):
    """Experiments 1-4. Tampering is done only on temporary copies."""
    originals = [args.document, args.signature, args.public_key]
    before = {str(p): sha256_file(p) for p in originals}
    rows = []

    def record(name, expected, result):
        observed = "VERIFIED" if result.ok else "FAILED"
        rows.append((name, expected, observed, "PASS" if observed == expected else "UNEXPECTED"))
        print(f"\n{name}\n  Expected: {expected}\n  Observed: {observed}\n  Detail:   {result.reason}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        record("E1 Original document + correct key", "VERIFIED",
               cu.verify_file(args.document, args.signature, args.public_key))

        doc_bytes = bytearray(cu.read_bytes(args.document))
        if doc_bytes:
            doc_bytes[0] ^= 0x01          # flip one bit of the first byte
        else:
            doc_bytes.append(0x58)
        tampered_doc = tmp / "document_tampered.txt"
        tampered_doc.write_bytes(bytes(doc_bytes))
        record("E2 Modified document (1 bit changed)", "FAILED",
               cu.verify_file(tampered_doc, args.signature, args.public_key))

        other_priv, other_pub = tmp / "other_private.pem", tmp / "other_public.pem"
        cu.generate_keypair(other_priv, other_pub)
        record("E3 Wrong public key (independent key pair)", "FAILED",
               cu.verify_file(args.document, args.signature, other_pub))

        sig_bytes = bytearray(cu.read_bytes(args.signature))
        sig_bytes[0] ^= 0x01
        bad_sig = tmp / "signature_modified.bin"
        bad_sig.write_bytes(bytes(sig_bytes))
        record("E4a Modified signature (1 bit changed)", "FAILED",
               cu.verify_file(args.document, bad_sig, args.public_key))

        short_sig = tmp / "signature_truncated.bin"
        short_sig.write_bytes(bytes(sig_bytes[:10]))
        record("E4b Truncated signature (malformed length)", "FAILED",
               cu.verify_file(args.document, short_sig, args.public_key))

    after = {str(p): sha256_file(p) for p in originals}
    unchanged = before == after

    print("\n" + "=" * 78)
    print(f"{'Test':<46}{'Expected':<10}{'Observed':<10}Check")
    print("-" * 78)
    for name, exp, obs, chk in rows:
        print(f"{name:<46}{exp:<10}{obs:<10}{chk}")
    print("-" * 78)
    print("Original document, signature and public key unchanged:", "YES" if unchanged else "NO")
    return 0 if unchanged and all(r[3] == "PASS" for r in rows) else 1


def cmd_demo_substitution(args):
    """Experiment 5: public-key substitution in a controlled simulation."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        print("STEP 1: Legitimate author signs a genuine document")
        author_priv, author_pub = tmp / "author_private.pem", tmp / "author_public.pem"
        author_fp = cu.generate_keypair(author_priv, author_pub)
        genuine = tmp / "genuine.txt"
        genuine.write_text("Certificate issued by Legitimate Author to Alice.\n")
        genuine_sig = cu.sign_file(genuine, author_priv, tmp / "genuine.sig")
        trusted_fp = author_fp   # assume verifier got this via an authenticated channel
        print(f"  Author's fingerprint (trusted, obtained out-of-band): {trusted_fp}")
        show(cu.verify_file(genuine, genuine_sig, author_pub))

        print("\nSTEP 2: Attacker generates their OWN key pair")
        atk_priv, atk_pub = tmp / "attacker_private.pem", tmp / "attacker_public.pem"
        atk_fp = cu.generate_keypair(atk_priv, atk_pub)
        print(f"  Attacker's fingerprint: {atk_fp}")

        print("\nSTEP 3: Attacker swaps the key on the GENUINE document (forgery attempt)")
        print("  Verifying author's genuine document + signature with attacker's key:")
        show(cu.verify_file(genuine, genuine_sig, atk_pub))
        print("  -> Key swapping does NOT let the attacker forge the author's signature.")

        print("\nSTEP 4: Attacker signs a DIFFERENT (fake) document with their own key")
        fake = tmp / "fake.txt"
        fake.write_text("Certificate issued by Legitimate Author to Mallory.\n")
        fake_sig = cu.sign_file(fake, atk_priv, tmp / "fake.sig")
        print("  Attacker sends fake.txt + fake.sig + attacker's public key,")
        print("  claiming they came from 'Legitimate Author'.")

        print("\nSTEP 5: NAIVE verifier trusts whatever public key arrives with the files")
        naive = cu.verify_file(fake, fake_sig, atk_pub)
        show(naive)
        if naive.ok:
            print("  -> Naive app wrongly concludes: 'Signed by Legitimate Author'.")
            print("     The signature is valid, but only for the ATTACKER's key.")

        print("\nSTEP 6: TRUSTED verifier checks key fingerprint against the pinned value")
        trusted = cu.verify_with_trusted_fingerprint(fake, fake_sig, atk_pub, trusted_fp)
        show(trusted)
        print("  Same trusted verifier on the genuine bundle:")
        genuine_trusted = cu.verify_with_trusted_fingerprint(
            genuine, genuine_sig, author_pub, trusted_fp)
        show(genuine_trusted)

        print("\nCONCLUSION: a valid signature proves possession of SOME private key, not")
        print("the claimed identity. Trust comes from authenticating the public key.")
        ok = naive.ok and (not trusted.ok) and genuine_trusted.ok
        return 0 if ok else 1


# ------------------------------------------------------------------- parser
def build_parser():
    p = argparse.ArgumentParser(description="Ed25519 document signing and verification")
    sub = p.add_subparsers(dest="command", required=True)

    k = sub.add_parser("keygen", help="generate an Ed25519 key pair")
    k.add_argument("--private-key", default=DEFAULT_PRIVATE, type=Path)
    k.add_argument("--public-key", default=DEFAULT_PUBLIC, type=Path)
    k.add_argument("--force", action="store_true", help="overwrite existing keys")
    k.set_defaults(func=cmd_keygen)

    s = sub.add_parser("sign", help="sign a document")
    s.add_argument("document", nargs="?", default=DEFAULT_DOCUMENT, type=Path)
    s.add_argument("--private-key", default=DEFAULT_PRIVATE, type=Path)
    s.add_argument("--output", default=DEFAULT_SIGNATURE, type=Path)
    s.set_defaults(func=cmd_sign)

    v = sub.add_parser("verify", help="verify a document's signature")
    v.add_argument("document", type=Path)
    v.add_argument("signature", type=Path)
    v.add_argument("public_key", type=Path)
    v.add_argument("--trusted-fingerprint", help="pinned SHA-256 key fingerprint (hex)")
    v.set_defaults(func=cmd_verify)

    f = sub.add_parser("fingerprint", help="print a public key's fingerprint")
    f.add_argument("public_key", type=Path)
    f.set_defaults(func=cmd_fingerprint)

    e = sub.add_parser("experiments", help="run Experiments 1-4")
    e.add_argument("--document", default=DEFAULT_DOCUMENT, type=Path)
    e.add_argument("--signature", default=DEFAULT_SIGNATURE, type=Path)
    e.add_argument("--public-key", default=DEFAULT_PUBLIC, type=Path)
    e.set_defaults(func=cmd_experiments)

    d = sub.add_parser("demo-substitution", help="run Experiment 5")
    d.set_defaults(func=cmd_demo_substitution)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except cu.InputError as exc:
        print(f"[INPUT ERROR] {exc}")
        print("This is an application/input problem, not a verification verdict.")
        return 2


if __name__ == "__main__":
    sys.exit(main())