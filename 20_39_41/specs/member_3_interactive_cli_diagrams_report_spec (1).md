# AI Agent Specification: Member 3 — Interactive Prototype (`app.py`), Diagrams & Project Report (`REPORT.md` & `README.md`)

## 1. Project Context & Role
You are a Full-Stack Security Engineer & Technical Writer building the interactive user interface (`app.py`), project documentation (`README.md`), and the comprehensive academic security report (`REPORT.md`) for **Project 2: Secure Messaging With Digital Signatures**.
Your application imports `crypto_core.py` (Member 1) and `experiments.py` (Member 2).
You must use Python 3.10+, `cryptography`, and `rich` (`pip install cryptography rich`).

---

## 2. Dependency Contract with Member 1 & Member 2
* From `crypto_core`: `PublicKeyDirectory`, `User`, `SecurityError`
* From `experiments`: `run_all_experiments`, `exp0_baseline`, `exp1_message_modification`, `exp2_impersonation_attempt`, `exp3_public_key_substitution`, `exp4_confidentiality_analysis`, `exp5_replay_attack`

---

## 3. Deliverable 1: Interactive CLI Application (`app.py`)
Build an interactive, crash-proof command-line messaging simulator using `rich.console.Console` and `rich.prompt.Prompt` that allows a user or grading professor to interactively explore every feature of the prototype.

### Required Interactive Menu Options:
1. **`[1] View Key Directory & Trusted Fingerprints`**
   * Displays a formatted table of registered users (`Alice`, `Bob`, `Mallory`), their 32-byte Ed25519 Public Keys (hex), and their trusted Out-of-Band SHA-256 Fingerprints.
2. **`[2] Send Signed Message (Alice <-> Bob)`**
   * Prompts user to choose Sender (`Alice` or `Bob`), Recipient, and enter a custom message text.
   * Prompts whether to enable the **Optional AES-256-GCM Confidentiality Extension** (`y/n`).
   * Generates the signed packet, displays the transmitted JSON packet on the "Network Wire" (showing plaintext vs. Base64 ciphertext + nonce + Ed25519 signature), and immediately runs the recipient's verification and prints the result panel.
3. **`[3] Interactive Attacker Sandbox (Tamper / Impersonate / Substitute Key / Replay)`**
   * Takes the most recently sent message (or creates a new one) and lets the user choose an live attack to perform before delivering to Bob:
     * **3a. Modify Message Payload in Transit** (user types new fake text without re-signing).
     * **3b. Corrupt Signature Bytes** (flips 1 byte of the Ed25519 signature).
     * **3c. Impersonate Sender** (signs with Mallory's private key while claiming `"sender": "Alice"`).
     * **3d. Public-Key Substitution** (swaps Alice's key in directory with Mallory's key, and lets user toggle Fingerprint Defense ON/OFF).
     * **3e. Replay Captured Packet** (resends the exact same packet a second time, and lets user toggle Replay Defense ON/OFF).
4. **`[4] Run All 5 Automated Rubric Security Experiments`**
   * Calls `run_all_experiments(export_artifacts=True)` from `experiments.py` and confirms that `artifacts/sample_results.json`, `artifacts/alice_public.pem`, and `artifacts/bob_public.pem` have been saved.
5. **`[5] Exit`**

### Command-Line Flag Support:
Also support running `python app.py --test` or `python app.py --experiments` from the terminal so automated grading scripts can run all experiments non-interactively and exit with code `0`.

---

## 4. Deliverable 2: Setup & Execution Guide (`README.md`)
Generate a clean, professional `README.md` containing:
1. Project overview and architecture table showing the 3 modules (`crypto_core.py`, `experiments.py`, `app.py`).
2. Prerequisites and exact 2-step installation commands (`pip install cryptography rich`).
3. Instructions for running the interactive simulator (`python app.py`) and the automated security test suite (`python experiments.py`).
4. Explanation of generated files in `artifacts/` and why private keys are never stored in the repository.

---

## 5. Deliverable 3: Complete Technical Report (`REPORT.md`)
Generate a thorough, academic-grade `REPORT.md` (which can be exported to PDF) covering all required sections in the Project 2 syllabus:

### Required Report Sections & Mermaid Diagrams:
1. **System Design & Architecture**
   * Explain the choice of Python's `cryptography` library and the **Ed25519** signature scheme (128-bit security level, 32-byte public keys, 64-byte signatures, deterministic nonce generation avoiding Sony PS3 ECDSA-style k-reuse bugs, resistance to side-channel timing attacks).
   * Include **Mermaid Sequence Diagrams** for:
     * Normal Signing, Verification, and Optional AES-GCM Encrypt-then-Sign flow.
     * Public-Key Substitution Attack vs. Out-of-Band Fingerprint Verification.
     * Replay Attack vs. Signed Monotonic Counter Defense.
2. **Envelope Specification & Canonicalization**
   * Document the exact JSON packet structure and explain why canonical JSON serialization (`sort_keys=True`) is critical so both sender and receiver verify the exact same byte sequence.
   * Explain why metadata (`sender`, `recipient`, `counter`, `timestamp`, `nonce`) MUST be placed inside the signed envelope rather than outside it.
3. **Detailed Analysis of the 5 Security Experiments**
   * For each of the 5 experiments (Message Modification, Impersonation, Public-Key Substitution, Confidentiality Analysis + AES-GCM Extension, Replay Attack + Defense):
     * State the **Hypothesis**, **Attack Procedure**, **Observed Result** (referencing the status codes and artifacts), and **Mathematical/Cryptographic Explanation**.
4. **Deep-Dive Answers to Core Security Questions**
   * Why digital signatures provide integrity and non-repudiation/authenticity, but NOT confidentiality.
   * How Encrypt-then-Sign with AES-256-GCM + Ed25519 protects both confidentiality and authenticity.
   * Why a valid signature under an unauthenticated public key does not prove real-world identity, and how Key Fingerprints, PKI/X.509 Certificate Authorities, and Key Transparency solve the trust bootstrap problem.
   * How sequence counters, UUID nonces, and timestamps prevent replay attacks, along with their state-synchronization trade-offs.