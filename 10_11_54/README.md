# X25519 Diffie–Hellman Key Exchange, MITM Attack, and Authenticated Defense

An educational applied cryptography simulation in Python 3.11+ demonstrating elliptic-curve Diffie–Hellman key agreement (`X25519`), active Man-in-the-Middle (`MITM`) interception, authenticated key exchange via `Ed25519` digital signatures and an out-of-band trusted key registry, `HKDF-SHA-256` key derivation with domain separation, and `AES-GCM` authenticated encryption with tampering detection.

---

## 1. Project Structure

```text
project3/
├── main.py                  # CLI entry point and scenario runner
├── crypto_utils.py          # Core cryptographic primitives and validation helpers
├── scenarios.py             # Scenarios A (Normal), B (MITM), C (Authenticated), D (Tamper)
├── requirements.txt         # External Python package dependencies
├── README.md                # Setup, usage, and operational documentation
├── report.md                # Academic report and experimental analysis
├── protocol_diagrams.md     # Mermaid sequence diagrams for all key exchange flows
└── tests/
    └── test_project.py      # Automated unittest suite (15 test cases)