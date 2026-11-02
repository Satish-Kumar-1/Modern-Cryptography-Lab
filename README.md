# Digital Signature-Based Document Verification (Ed25519)

Project 4, Modern Cryptography + Lab (25CS2743), Shiv Nadar University Chennai.
Team: P Yagna Sanjeev (25011103036), Rohith M (25011103028).

A command-line tool that signs a document with Ed25519 and verifies it using a
detached signature and a public key. Built in Python with the `cryptography` library.

## Setup (macOS)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
# Verify the included sample (works with only the public files in this repo)
python3 main.py verify sample_document.txt artifacts/signature.bin artifacts/public_key.pem

# Run experiments 1-4 on temporary copies and experiment 5 (public-key substitution)
python3 main.py experiments
python3 main.py demo-substitution

# Automated tests
python3 -m unittest -v tests.test_signatures
```

To create your own keys (private key is saved to `~/.dsig_keys/`, never in this repo):
```bash
python3 main.py keygen --force
python3 main.py sign
```
Note: this replaces `artifacts/public_key.pem` and `artifacts/signature.bin`.

## Exit codes
0 = verified, 1 = verification failed, 2 = input error.

## Security notes
- The private key is never included in this repository.
- Only the public key, signature and sample document are provided for verification.
- Full report: `report/`.