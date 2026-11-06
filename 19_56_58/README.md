
# Diffie–Hellman Key Exchange and Man-in-the-Middle Attack

## Overview

This project demonstrates X25519 key agreement, HKDF-SHA256 key derivation, AES-256-GCM authenticated encryption, and Ed25519 authentication.

It simulates an unauthenticated man-in-the-middle (MITM) attack and demonstrates how digital signatures can detect substituted key-agreement public keys.

All simulations run locally and use the Python cryptography library.

## Requirements

- Python 3.14.10
- cryptography 50.0.2

## Setup

Create and activate a virtual environment if one does not already exist.

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Run the simulations

Run the unauthenticated MITM simulation tests:

```powershell
.\.venv\Scripts\python.exe test_protocol.py
```

Run the edge-case tests:

```powershell
.\.venv\Scripts\python.exe test_edge_cases.py
```

Run the individual modules if needed:

```powershell
.\.venv\Scripts\python.exe key_exchange.py
.\.venv\Scripts\python.exe key_derivation.py
.\.venv\Scripts\python.exe encryption.py
.\.venv\Scripts\python.exe authentication.py
```

The individual modules define functions and may produce no output when executed directly. Use the test files to verify their behavior.

## Security notes

- X25519 establishes a shared secret but does not authenticate the communicating parties.
- HKDF derives application keys from shared secret material.
- AES-GCM provides authenticated encryption and detects ciphertext tampering.
- Ed25519 signatures authenticate the X25519 public keys in the demonstration.
- The authenticated simulation assumes the trusted Ed25519 public keys were provisioned securely beforehand.
- The MITM simulations are educational and do not intercept real network traffic.

## Test results

All simulations and tests run entirely locally in memory without network sockets or external traffic.

Latest test suite execution results:

| Test Suite | Scope & Description | Tests / Assertions | Status |
|---|---|:---:|:---:|
| `test_edge_cases.py` | Unit tests for AES-GCM tags, nonces, key lengths, context/identity binding (sender, recipient, protocol ID), and protocol states | 11 tests | **PASS** |
| `test_protocol.py` | End-to-end unauthenticated MITM, authenticated exchange, and MITM rejection simulations | 3 scenarios | **PASS** |
| `test_authentication.py` | Ed25519 signature validity, forged identity rejection, and public key substitution checks | 3 checks | **PASS** |
| `test_encryption.py` | AES-256-GCM ciphertext and tag tampering detection | 1 test | **PASS** |
| `test_invalid_key.py` | Rejection of non-32-byte AES symmetric keys | 1 test | **PASS** |

Total: 5 test suites (19 test cases / assertion groups) executed; 0 failures, 0 errors.
