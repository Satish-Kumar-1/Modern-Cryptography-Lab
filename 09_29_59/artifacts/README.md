# Verification Artifacts

This directory contains the public verification artifacts generated for **Project 4: Digital Signature-Based Document Verification**, satisfying Functional Requirement 4, Requirement 8, and Deliverable 3.

## Contents

1. **`signer_public_key.pem`**:
   - The authentic Ed25519 public key of the document signer.
   - Encoded in standard SubjectPublicKeyInfo (SPKI) PEM format (RFC 8410 / RFC 5280).
   - This file is distributed publicly so any verifier can validate documents signed by this identity.

2. **`sample_document.sig`**:
   - Detached 64-byte Ed25519 digital signature of `sample_data/sample_document.txt`.
   - Stored independently of the original document.

## Security Notice (Requirement 8)

In strict compliance with **Requirement 8 (Secure Key Management)**:
> *"Protect the private signing key and ensure it is not included in public submissions or source-code repositories. Include only the public key and required verification artifacts in the submission."*

The private signing key used to sign `sample_document.txt` has been excluded from this repository and version control. Only the public key and verification artifacts are supplied.
