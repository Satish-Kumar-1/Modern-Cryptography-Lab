# Security Experiments and Results

This document records the five required digital-signature experiments for
Project 4. The tests use Ed25519 through the `cryptography` library.

Run the complete test suite from the repository root:

```bash
python -m unittest discover tests -v
```

## Experiment 1 — Verify the original document

**Setup:** Sign the original document with the author's Ed25519 private key.
Verify it using the matching public key and detached signature.

**Expected result:** Verification succeeds.

**Observed result:** PASS. `SignatureVerifier.verify_document()` returns
`is_valid=True`.

## Experiment 2 — Modify the signed document

**Setup:** Change at least one byte in the document while keeping the original
signature and public key.

**Expected result:** Verification fails because the signature covers the exact
original byte sequence.

**Observed result:** PASS. Verification returns `is_valid=False`.

## Experiment 3 — Supply the wrong public key

**Setup:** Keep the original document and signature, but supply an unrelated
Ed25519 public key.

**Expected result:** Verification fails.

**Observed result:** PASS. Verification returns `is_valid=False`.

## Experiment 4 — Modify or replace the signature

**Setup:** Change a byte in the 64-byte detached signature while keeping the
original document and public key.

**Expected result:** Verification fails.

**Observed result:** PASS. Verification returns `is_valid=False`.

## Experiment 5 — Public-key substitution

**Setup:**
1. The legitimate author has a public key whose fingerprint was received
   through a trusted, authenticated channel.
2. An attacker creates their own Ed25519 key pair.
3. The attacker signs a replacement document with their own private key.
4. The attacker supplies the replacement document, their signature, and their
   own public key.

**Expected result:** Mathematical signature verification under the attacker's
supplied public key succeeds. However, the attacker's public-key fingerprint
does not match the previously trusted fingerprint for the legitimate author,
so the key-trust check rejects the substitution.

**Observed result:** PASS. The test confirms both conditions:
- `SignatureVerifier.verify_document()` returns `is_valid=True` for the
  attacker's document/signature/public-key combination.
- `KeyFingerprint.verify_fingerprint()` returns `False` when the attacker's
  public key is compared with the legitimate author's trusted fingerprint.

**Security interpretation:** A valid digital signature proves that the
signature matches the message under the supplied public key. It does not, by
itself, prove the real-world identity of the person controlling that key.
The verifier must authenticate the association between the public key and
the claimed signer, for example by checking a fingerprint communicated over
a trusted channel.

## Additional robustness tests

The automated suite also checks malformed signatures, malformed public keys,
missing files, invalid argument types, fingerprint mismatches, and consistent
fingerprints across PEM, raw-byte, and in-memory public-key representations.

## Test summary

The project test suite currently contains **34 tests** across four test modules (`test_key_generation.py`, `test_sign_verify.py`, `test_security_experiments.py`, and `test_cli.py`), all passing in the development environment used for this validation.
