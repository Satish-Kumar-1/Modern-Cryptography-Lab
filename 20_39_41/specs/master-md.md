# MASTER AI AGENT SPECIFICATION: Project 2 — Secure Messaging With Digital Signatures (`ed25519-secure-messaging`)

## 1. Mission & Execution Context
You are an autonomous Principal Cryptography & Security Software Engineer executing inside **Antigravity** on a Windows `MINGW64` (Git Bash) workspace (`~/Desktop/Projects/ed25519-secure-messaging`).
Your objective is to build, test, and verify the **complete 3-member cryptography engineering project** end-to-end:
* **Member 1 (`crypto_core.py`):** Core Ed25519 digital signatures, optional AES-256-GCM Encrypt-then-Sign confidentiality layer, SHA-256 Out-of-Band Key Fingerprint directory, and stateful replay protection.
* **Member 2 (`experiments.py`):** Automated 5-attack simulation & defense evaluation suite with `rich` terminal visualizations and JSON/public-key artifact generation.
* **Member 3 (`app.py`, `README.md`, `docs/REPORT.md`):** Interactive crash-proof CLI simulator and live MITM attacker sandbox, setup documentation, Mermaid sequence diagrams, and academic security analysis report.

---

## 2. Target Repository Architecture
You must create and populate this exact directory structure:

```text
ed25519-secure-messaging/
├── .gitignore                        # Blocks private keys (*.pem), __pycache__, and .venv
├── requirements.txt                  # Python dependencies (cryptography, rich)
├── README.md                         # Architecture, threat model, setup, and usage guide
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
│   └── bob_public_key.pub            # Exported public key in PEM encoding (tracked in Git)
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
    ├── member1_crypto_core_spec.md
    ├── member2_experiments_spec.md
    └── member3_cli_and_report_spec.md