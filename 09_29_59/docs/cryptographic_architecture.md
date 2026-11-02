# Cryptographic Architecture & Technical Specification

**Project:** Digital Signature-Based Document Verification (University Project 4)  
**Author:** Person 1 (Cryptographic Core & Key Management Lead)  
**Target Audience:** Person 2 (Security Lead), Person 3 (Application Lead), Faculty Reviewers  

---

## 1. Cryptographic Scheme: Ed25519 (RFC 8032)

This project implements digital signatures using **Ed25519**, the Edwards-curve Digital Signature Algorithm (EdDSA) instantiated over **Curve25519**.

### 1.1 Mathematical Foundation
* **Curve Equation:** Defined over the prime field $\mathbb{F}_{2^{255}-19}$ by the twisted Edwards curve:
  $$-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2$$
* **Base Point Order ($L$):** $L = 2^{252} + 27742317777372353535851937790883648493$ (a 252-bit prime).
* **Hash Function:** SHA-512 (RFC 6234).
* **Key Dimensions:**
  * **Private Key Seed:** 32 bytes (256 bits).
  * **Public Key:** 32 bytes (compressed coordinate $y$ with the sign bit of $x$).
  * **Signature:** Exactly 64 bytes: concatenation of curve point $R$ (32 bytes) and scalar $S$ (32 bytes).

### 1.2 Why Ed25519 Was Selected Over RSA and ECDSA
1. **Deterministic Signature Generation:**  
   Unlike ECDSA (ANSI X9.62) which requires a cryptographically secure random per-message nonce $k$, Ed25519 generates the nonce deterministically:
   $$r = \text{SHA-512}(h_b \parallel \dots \parallel h_{2b-1} \parallel M) \pmod L$$
   This eliminates catastrophic private key exposure caused by weak, repeated, or biased random number generators (e.g., the infamous Sony PlayStation 3 ECDSA flaw).
2. **Side-Channel Immunity:**  
   Point addition and doubling on twisted Edwards curves are unified and complete. Operations run in constant time with no conditional branching or cache lookups based on secret key bits, making it naturally resistant to timing and cache side-channel attacks.
3. **High Performance & Compact Footprint:**  
   Verification and signing operations execute significantly faster than RSA-2048/4096 or standard NIST P-256 curves, requiring only 64-byte detached signatures.

---

## 2. Cryptographic Library Selection

In accordance with **Requirement 1**, an established, production-grade cryptographic library was selected:
* **Library:** `cryptography` (Python Cryptographic Authority, PyCA).
* **Underlying Engine:** OpenSSL 3.x / C-bindings.
* **Standards Compliance:** RFC 8032, FIPS 186-5, RFC 5280, RFC 8410.

---

## 3. Component Architecture & Person 1 Deliverables

```
src/
├── key_manager.py          # Person 1: Key generation, PKCS#8 / SPKI serialization, file storage
├── document_signer.py      # Person 1: Detached signing, exact byte integrity
├── signature_verifier.py   # Person 1/2: Verification engine, error handling without crashing
└── key_fingerprint.py      # Person 1/2: Canonical SHA-256 public key fingerprinting
```

### 3.1 `KeyManager` (`src/key_manager.py`)
Responsible for lifecycle management of asymmetric keys:
* `generate_key_pair() -> (Ed25519PrivateKey, Ed25519PublicKey)`:  
  Generates a fresh key pair seeded by OS entropy (`os.urandom`).
* `save_private_key(private_key, file_path, password=None)`:  
  Serializes the private key into PKCS#8 PEM format. If `password` is supplied, it encrypts the private key at rest using `BestAvailableEncryption` (AES-256-CBC with PBKDF2/scrypt). Enforces `0600` POSIX file permissions.
* `save_public_key(public_key, file_path)`:  
  Serializes the public key into standard SubjectPublicKeyInfo (SPKI) PEM format (RFC 8410).
* `load_private_key(source, password=None)`:  
  Loads private key from file or bytes. Raises `InvalidPassphraseError`, `KeyFormatError`, or `FileNotFoundError` with clear error explanations.
* `load_public_key(source)`:  
  Loads public key from SPKI PEM or 32 raw bytes. Rejects malformed input safely without crashing.

### 3.2 `DocumentSigner` (`src/document_signer.py`)
Responsible for detached digital signing:
* `sign_bytes(data: bytes, private_key: Ed25519PrivateKey) -> bytes`:  
  Computes the 64-byte Ed25519 signature over exact byte payload.
* `sign_document(document_path, private_key, signature_output_path=None, password=None) -> bytes`:  
  Reads the document file in binary mode (`"rb"`). **Crucially preserves every byte, byte-order, whitespace, and newline** without transformation. Writes detached `.sig` file if requested.

### 3.3 `SignatureVerifier` (`src/signature_verifier.py`)
* `verify_document(document_path, signature_source, public_key_source) -> VerificationResult`:  
  Loads document bytes, signature (64 bytes), and public key. Returns structured result with status boolean and human-readable explanation.
* **Safe Error Handling:** Catching `InvalidSignature`, file errors, and malformed inputs without unhandled crashes.

### 3.4 `KeyFingerprint` (`src/key_fingerprint.py`)
* `compute_fingerprint(public_key) -> str`:  
  Computes `SHA256:xx:xx:...` over the DER SubjectPublicKeyInfo representation of the public key.
* `verify_fingerprint(public_key, expected_fingerprint) -> bool`:  
  Constant-time string comparison (`hmac.compare_digest`) to verify key trust out-of-band.

---

## 4. Key Security Principles & Analysis Answers

### 4.1 Digital Signatures vs. Encryption (Assignment Question 2)
* **Digital Signatures:** Guarantee **Authenticity**, **Data Integrity**, and **Non-Repudiation**.  
  A digital signature does **NOT** conceal document contents. The document remains in plaintext and can be read by anyone. The signature is simply a 64-byte cryptographic proof that the holder of the corresponding private key approved that exact byte sequence.
* **Encryption:** Guarantees **Confidentiality**.  
  Encryption transforms plaintext into ciphertext so that only authorized parties with the decryption key can read it.

### 4.2 Private Key Management & Version Control Security (Requirement 8 & Question 5)
* **The Golden Rule:** Private signing keys must **never** be committed to public repositories or shared.
* If an attacker obtains the private key, they can forge signatures on arbitrary documents with full cryptographic validity. The entire trust model collapses.
* **Protection Mechanisms Implemented:**
  1. `.gitignore` explicitly filters `*.key`, `*.priv`, `*private*`, `*.pkcs8`, `private/`.
  2. Optional passphrase encryption using PBKDF2 + AES-256 at rest.
  3. Submission artifacts contain **only** `signer_public_key.pem`, `sample_document.sig`, and `sample_document.txt`. Real private keys are never stored in the repository.

---

## 5. Interface Guide for Teammates

### For Person 2 (Security and Testing Lead)
* You can import `KeyManager`, `DocumentSigner`, `SignatureVerifier`, and `KeyFingerprint` directly from `src`.
* The baseline tests are located in `tests/test_sign_verify.py` and `tests/test_key_generation.py`.
* All 5 required experiments can be built cleanly upon this module foundation.

### For Person 3 (Application & Integration Lead)
* For the CLI or GUI, you only need to call:
  ```python
  from src.key_manager import KeyManager
  from src.document_signer import DocumentSigner
  from src.signature_verifier import SignatureVerifier
  from src.key_fingerprint import KeyFingerprint
  ```
* All methods accept either file paths (`str` or `Path`) or in-memory objects, making them simple to bind to file pickers or command-line arguments.
