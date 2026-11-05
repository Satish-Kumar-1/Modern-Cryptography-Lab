# Ed25519 Secure Messaging & Active MITM Attack Simulator

An interactive cryptographic messaging prototype and offensive security testbed built in **Python 3.10+** using `cryptography` and `rich`.

This project implements an authenticated messaging protocol between participants (`Alice` and `Bob`) over an untrusted network controlled by an active Dolev-Yao adversary (`Mallory`). It demonstrates how **Ed25519 (RFC 8032)** digital signatures enforce **message integrity**, **sender authenticity**, and **non-repudiation**, while exposing—and defending against—protocol-level vulnerabilities including **in-transit tampering**, **key-directory poisoning (Public-Key Substitution)**, **cleartext metadata/payload exposure**, and **packet replay attacks**.

---

## 1. Core Cryptographic Architecture

The protocol layers asymmetric digital signatures, authenticated symmetric encryption, out-of-band key pinning, and stateful replay tracking into a deterministic verification pipeline:

* **Digital Signatures (`Ed25519` / RFC 8032):** Provides 128-bit security ($\approx$ 3072-bit RSA) with compact 32-byte public keys and 64-byte signatures. Uses deterministic SHA-512 nonce derivation to eliminate random-number-generator ($k$-reuse) vulnerabilities and branchless Twisted Edwards curve arithmetic for side-channel resistance.
* **Confidentiality Extension (`AES-256-GCM` Encrypt-then-Sign):** Because digital signatures do not hide message contents, the protocol includes an optional **Encrypt-then-Sign (EtS)** layer using 256-bit AES in Galois/Counter Mode with a 96-bit CSPRNG nonce (`os.urandom(12)`). The outer Ed25519 signature covers both the Base64 ciphertext and the GCM nonce, preventing attackers from feeding unauthenticated ciphertexts into the decryption routine.
* **Out-of-Band Key Authentication (`SHA-256` Fingerprints):** Simulates a public-key registry alongside a pinned out-of-band fingerprint store (`SHA-256` digest of the raw 32-byte Ed25519 public key) to detect Public-Key Substitution (MITM key-swapping) attacks.
* **Stateful Replay Protection:** Combines monotonically increasing per-sender sequence counters (`counter`), 128-bit UUIDv4 message IDs (`msg_id`), and bounded UTC timestamps (`max_age_seconds = 300`) inside the signed envelope to prevent packet capture-and-replay attacks.

---

## 2. Wire Packet Format & Canonical Serialization

Every transmitted message is encapsulated as a JSON packet containing a signed `"envelope"` and a Base64-encoded 64-byte `"signature"`:

```json
{
  "envelope": {
    "counter": 1,
    "encrypted": false,
    "msg_id": "a4f9d210-7c4e-4b89-9d1a-88c3e5f01234",
    "nonce": null,
    "payload": "Transfer $500 to project escrow account #8821.",
    "recipient": "Bob",
    "sender": "Alice",
    "timestamp": 1730000000
  },
  "signature": "base64-encoded-64-byte-ed25519-signature"
}
```

### Deterministic Canonicalization
To prevent signature verification failures caused by arbitrary JSON serialization discrepancies (whitespace, dictionary key order), the envelope is converted to canonical UTF-8 bytes prior to signing and verification:
```python
canonical_bytes = json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode('utf-8')
```

---

## 3. Project Structure

```text
ed25519-secure-messaging/
├── .gitignore                        # Blocks private keys (*.pem), __pycache__, and .venv
├── requirements.txt                  # Python dependencies (cryptography, rich)
├── README.md                         # Architecture, threat model, setup, and usage guide
├── MASTER_PROJECT_SPEC.md            # Comprehensive project master specification
│
├── crypto_core.py                    # [Member 1] Key gen, Ed25519 sign/verify, AES-GCM, PKI directory
├── experiments.py                    # [Member 2] Automated 5-attack simulation & defense test suite
├── app.py                            # [Member 3] Interactive CLI menu for Alice, Bob, and Attacker
│
├── artifacts/                        # Sample messages, public keys, & test output logs
│   ├── sample_signed_packet.json     # Example JSON packet showing message + signature + metadata
│   ├── sample_encrypted_packet.json  # Example packet with AES-GCM confidentiality enabled
│   ├── sample_results.json           # Complete audit log of Baseline + 5 Security Experiments
│   ├── alice_public_key.pub          # Exported public key in PEM encoding
│   ├── bob_public_key.pub            # Exported public key in PEM encoding
│   ├── alice_public.pem              # Exported public key in PEM encoding
│   └── bob_public.pem                # Exported public key in PEM encoding
│
├── docs/                             # [Deliverables 5 & 6] Presentation, source report, diagrams, & logs
│   ├── REPORT.md                     # Full security analysis reference notes (Markdown source)
│   ├── REPORT_Presentation.pptx      # Final generated PowerPoint slide deck for grading/presentation
│   ├── diagrams/                     # Architecture & attack flow diagrams (PNG/SVG/Mermaid)
│   │   ├── 01_normal_and_aesgcm_flow.mmd
│   │   ├── 02_public_key_substitution.mmd
│   │   └── 03_replay_attack_defense.mmd
│   └── screenshots/                  # Terminal screenshots of all experiments & CLI runs
│       ├── 01_normal_exchange.png
│       ├── 02_tampering_rejected.png
│       ├── 02b_corrupted_signature_rejected.png
│       ├── 03_impersonation_rejected.png
│       ├── 04_key_substitution.png
│       ├── 05_confidentiality_aesgcm.png
│       └── 06_replay_defense.png
│
├── generate_ppt.py                   # Script to build dark-theme PPTX and embed terminal screenshots
│
└── specs/                            # Detailed specification files for reference
    ├── master-md.md
    ├── member_1_core_cryptography_key_directory_spec (1).md
    ├── member_2_security_experiments_attack_simulator_spec (1).md
    └── member_3_interactive_cli_diagrams_report_spec (1).md
```

---

## 4. Setup & Quickstart

### Prerequisites
* Python 3.10+ (tested on Python 3.10 through 3.14)
* pip package manager

### 1. Installation
Install project dependencies:
```bash
pip install -r requirements.txt
```

### 2. Verify Cryptographic Core
Execute unit tests and self-test verification:
```bash
python crypto_core.py
```

### 3. Run Automated Security Evaluation Suite
Run all baseline tests and 5 attack simulations:
```bash
python experiments.py
```

### 4. Launch Interactive CLI Simulator
Start the interactive terminal interface:
```bash
python app.py
```

To run all automated experiments non-interactively via the CLI entrypoint:
```bash
python app.py --test
```

---

## 5. Security Evaluation Matrix

| Experiment | Scenario | Threat Model | Defended? | Verification Status Code |
|---|---|---|:---:|---|
| **EXP-0** | Baseline Exchange | Normal authentic message flow between Alice and Bob | N/A | `SUCCESS` |
| **EXP-1** | Message Modification | 1 character altered in payload or 1 byte flipped in signature | Yes | `INVALID_SIGNATURE` |
| **EXP-2** | Impersonation Attempt | Mallory signs message claiming sender="Alice" with Mallory's key | Yes | `INVALID_SIGNATURE` |
| **EXP-3** | Public-Key Substitution | Mallory tampers with directory to register Mallory's key as Alice | Yes | `KEY_SUBSTITUTION_DETECTED` |
| **EXP-4** | Confidentiality Analysis | Eavesdropper reads unencrypted payload vs AES-256-GCM ciphertext | Yes | `AEAD_PROTECTED` |
| **EXP-5** | Replay Attack | Mallory resends captured valid packet or increments counter | Yes | `REPLAY_DETECTED` / `INVALID_SIGNATURE` |

---

## 6. Key Management & Security Policy
* **Public Keys:** Exported in SubjectPublicKeyInfo PEM format to `artifacts/alice_public.pem` and `artifacts/bob_public.pem`.
* **Private Keys:** Never serialized to persistent storage or committed to version control. Generated in-memory only.
* **Git Exclusions:** The `.gitignore` strictly prohibits `*.key`, `*private*.pem`, `secret*`, and virtual environment directories.