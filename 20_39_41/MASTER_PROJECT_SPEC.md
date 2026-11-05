# MASTER PROJECT SPECIFICATION: Project 2 — Secure Messaging With Digital Signatures (`ed25519-secure-messaging`)

## 1. Mission & Execution Context
You are an autonomous Principal Cryptography & Security Software Engineer executing inside **Antigravity** on a Windows workspace (`~/Desktop/Projects/ed25519-secure-messaging`).
Your objective is to build, test, and verify the **complete 3-member cryptography engineering project** end-to-end:
* **Member 1 (`crypto_core.py`):** Core Ed25519 digital signatures, optional AES-256-GCM Encrypt-then-Sign confidentiality layer, SHA-256 Out-of-Band Key Fingerprint directory, and stateful replay protection.
* **Member 2 (`experiments.py`):** Automated 5-attack simulation & defense evaluation suite with `rich` terminal visualizations and JSON/public-key artifact generation.
* **Member 3 (`app.py`, `README.md`, `docs/REPORT.md`):** Interactive crash-proof CLI simulator and live MITM attacker sandbox, setup documentation, Mermaid sequence diagrams, and academic security analysis report.

---

## 2. Target Repository Architecture
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
├── artifacts/                        # [Deliverable 3] Sample messages, public keys, & signatures
│   ├── sample_signed_packet.json     # Example JSON packet showing message + signature + metadata
│   ├── sample_encrypted_packet.json  # Example packet with AES-GCM confidentiality enabled
│   ├── sample_results.json           # Complete audit log of Baseline + 5 Security Experiments
│   ├── alice_public_key.pub          # Exported public key in PEM encoding (tracked in Git)
│   ├── bob_public_key.pub            # Exported public key in PEM encoding (tracked in Git)
│   ├── alice_public.pem              # Exported public key in PEM format
│   └── bob_public.pem                # Exported public key in PEM format
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
└── specs/                            # Individual specification files for reference
    ├── master-md.md
    ├── member_1_core_cryptography_key_directory_spec (1).md
    ├── member_2_security_experiments_attack_simulator_spec (1).md
    └── member_3_interactive_cli_diagrams_report_spec (1).md
```

---

## 3. Member 1 Specifications (`crypto_core.py`)
* **Ed25519 Digital Signatures:** `cryptography.hazmat.primitives.asymmetric.ed25519`
* **Optional AEAD Confidentiality:** AES-256-GCM (`AESGCM`), 12-byte nonce, Encrypt-then-Sign
* **Canonical JSON Serialization:** `json.dumps(envelope, sort_keys=True, separators=(',', ':')).encode('utf-8')`
* **Custom Exception:** `SecurityError(Exception)`
* **PublicKeyDirectory:**
  * `register_user(username, pub_key, update_trusted_fingerprint=True)`
  * `compute_fingerprint(pub_key) -> str` (SHA-256 hex digest of raw 32-byte public key)
  * `tamper_registry_key(username, fake_pub_key)`
  * `get_public_key(username, verify_fingerprint=True)`
  * `get_public_key_hex(username)`
* **User Class:**
  * Key generation, public key hex, fingerprint, PEM export
  * `sign_message(recipient, plaintext, shared_aes_key=None, custom_counter=None, custom_timestamp=None) -> dict`
  * `verify_message(packet, enforce_replay_defense=True, verify_key_fingerprint=True, shared_aes_key=None, max_age_seconds=300) -> dict`
  * Strict Verification Order of Operations:
    1. Validate packet structure (`envelope`, `signature`)
    2. Retrieve public key with out-of-band SHA-256 fingerprint validation (`KEY_SUBSTITUTION_DETECTED`)
    3. Ed25519 signature verification over canonical JSON (`INVALID_SIGNATURE`)
    4. Stateful replay defense (`counter`, `seen_messages`, timestamp window 300s) (`REPLAY_DETECTED`, `EXPIRED_TIMESTAMP`)
    5. AES-256-GCM decryption if `encrypted=True` (`DECRYPTION_FAILED`)
    6. Return `valid=True, status_code="SUCCESS"`
  * Self-test block asserting normal unencrypted and AES-GCM encrypted message flows pass.

---

## 4. Member 2 Specifications (`experiments.py`)
* **Baseline + 5 Security Experiments:**
  1. `exp0_baseline`: Authentic message exchange between Alice and Bob.
  2. `exp1_message_modification`: 1-character payload tampering and 1-byte signature corruption in transit.
  3. `exp2_impersonation_attempt`: Attacker signs message claiming Alice's identity using attacker's own private key.
  4. `exp3_public_key_substitution`: Key substitution in directory (Part A: unauthenticated directory vulnerable; Part B: out-of-band SHA-256 fingerprint catches substitution).
  5. `exp4_confidentiality_analysis`: Signature-only exposure vs. AES-256-GCM Encrypt-then-Sign confidentiality.
  6. `exp5_replay_attack`: Part A: Replay attack accepted without defense; Part B: Monotonic counter & seen set blocks replay; Part C: Counter tampering breaks Ed25519 signature.
* **Automated Runner:** `run_all_experiments(export_artifacts=True)` generating `artifacts/sample_results.json`, `artifacts/alice_public.pem`, `artifacts/bob_public.pem`.
* **Rich Visualizations:** `rich.console.Console`, `rich.table.Table`, `rich.panel.Panel`.

---

## 5. Member 3 Specifications (`app.py`, `README.md`, `REPORT.md`)
* **Interactive CLI Simulator (`app.py`):**
  * Option 1: View Key Directory & Trusted Fingerprints
  * Option 2: Send Signed Message (Alice <-> Bob, optional AES-GCM)
  * Option 3: Interactive Attacker Sandbox (Tamper, Corrupt, Impersonate, Substitute, Replay)
  * Option 4: Run All 5 Automated Rubric Security Experiments
  * Option 5: Exit
  * CLI flag support: `--test` and `--experiments`
* **Documentation & Academic Report:**
  * `README.md`: Architecture, threat model, setup commands, usage guide, artifacts overview.
  * `docs/REPORT.md`: Comprehensive academic report with complete system architecture, mathematical explanations, envelope specification, in-depth analysis of all 5 experiments, and core security question deep dives.
  * `docs/diagrams/`: Mermaid sequence diagrams (`01_normal_and_aesgcm_flow.mmd`, `02_public_key_substitution.mmd`, `03_replay_attack_defense.mmd`).

---

## 6. Security Architecture & Cryptographic Threat Model
* **Threat 1: In-Transit Tampering:** Addressed by Ed25519 signature over canonical JSON envelope.
* **Threat 2: Impersonation / Forgery:** Addressed by unforgeable Ed25519 signature based on ECDLP hardness.
* **Threat 3: Public-Key Substitution / Malicious Directory:** Addressed by SHA-256 key fingerprinting (out-of-band verification).
* **Threat 4: Eavesdropping / Passive Interception:** Addressed by optional AES-256-GCM Encrypt-then-Sign confidentiality.
* **Threat 5: Replay Attacks:** Addressed by stateful monotonic sequence counters, UUIDv4 message IDs, and UTC timestamps.

---

## 7. Autonomous 8-Step Execution Plan

### Step 1: Environment & Dependency Setup
* Ensure `requirements.txt` contains `cryptography>=41.0.0` and `rich>=13.0.0`.
* Update `.gitignore` to prevent leaking private keys (`*.key`, `*private*.pem`, `secret*`), `.venv/`, and `__pycache__/`.
* Verify the Python runtime and dependencies execute cleanly.

### Step 2: Implement Member 1 Core Cryptography Backend (`crypto_core.py`)
* Implement `SecurityError`, `PublicKeyDirectory`, and `User` in `crypto_core.py`.
* Ensure exact compliance with canonical JSON formatting and verification sequence.
* Implement the standalone self-test block.

### Step 3: Execute & Verify Member 1 Self-Tests
* Run `python crypto_core.py` directly.
* Ensure both unencrypted and AES-GCM signed messages verify with `valid=True`.

### Step 4: Implement Member 2 Automated Attack Simulation Suite (`experiments.py`)
* Implement `exp0_baseline` through `exp5_replay_attack`.
* Implement `run_all_experiments` with rich tables, color-coded status badges, and artifact export.

### Step 5: Execute & Verify Member 2 Security Experiments
* Run `python experiments.py`.
* Validate that all 6 experiments pass and `sample_results.json` and public key PEM files are written.

### Step 6: Implement & Verify Member 3 Interactive CLI Simulator (`app.py`)
* Verify `app.py` integration with `crypto_core.py` and `experiments.py`.
* Ensure `--test` and `--experiments` run non-interactively and return exit code 0.
* Verify `ensure_repo_artifacts()` populates all required packet samples and keys.

### Step 7: Generate Standalone Mermaid Diagrams, Academic Security Report, and README
* Create standalone Mermaid sequence diagrams in `docs/diagrams/`.
* Write the comprehensive academic `docs/REPORT.md` including theoretical analysis and experimental evaluations.
* Ensure `README.md` is complete and accurately reflects project features and commands.

### Step 8: End-to-End System Verification, Artifact Auditing & Final Sign-Off
* Run test suites: `python crypto_core.py`, `python experiments.py`, `python app.py --test`.
* Audit all generated files in `artifacts/`:
  * `sample_signed_packet.json`
  * `sample_encrypted_packet.json`
  * `sample_results.json`
  * `alice_public_key.pub`
  * `bob_public_key.pub`
  * `alice_public.pem`
  * `bob_public.pem`
* Verify clean git status and absence of unencrypted private keys.

---

## 8. Deliverable Verification & Audit Matrix
| Deliverable | File Path | Status | Verification Check |
|---|---|---|---|
| Core Crypto Backend | `crypto_core.py` | Required | `python crypto_core.py` returns 0 |
| Attack Experiments | `experiments.py` | Required | `python experiments.py` returns 0 |
| Interactive CLI | `app.py` | Required | `python app.py --test` returns 0 |
| Signed Packet Sample | `artifacts/sample_signed_packet.json` | Required | Valid JSON envelope & signature |
| Encrypted Packet Sample | `artifacts/sample_encrypted_packet.json` | Required | Base64 AES-GCM ciphertext + nonce |
| Experiment Results Audit | `artifacts/sample_results.json` | Required | Complete logs for Baseline + 5 Attacks |
| Public Keys (PEM) | `artifacts/*.pub` & `artifacts/*.pem` | Required | Valid Ed25519 PEM public keys |
| Mermaid Diagrams | `docs/diagrams/*.mmd` | Required | Valid Mermaid syntax |
| Academic Report | `docs/REPORT.md` | Required | Complete 4-section analysis |
| Presentation Deck | `docs/REPORT_Presentation.pptx` | Required | Generated 11-slide presentation |
| Terminal Screenshots | `docs/screenshots/*.png` | Required | 7 experiment & CLI screenshots |
| Project README | `README.md` | Required | Complete setup, architecture, and guide |
