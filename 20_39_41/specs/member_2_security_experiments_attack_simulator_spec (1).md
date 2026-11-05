# AI Agent Specification: Member 2 — Security Analysis & Attack Simulator (`experiments.py`)

## 1. Project Context & Role
You are an Offensive Security & Cryptography Engineer building the automated attack simulation and security evaluation suite (`experiments.py`) for **Project 2: Secure Messaging With Digital Signatures**.
Your module imports `PublicKeyDirectory`, `User`, and `SecurityError` from Member 1's `crypto_core.py` and will also be called by Member 3's `app.py`.
You must use Python 3.10+, `cryptography`, and `rich` (`pip install cryptography rich`) to produce clean, screenshot-ready terminal tables and panels for all required experiments in the project rubric, plus dump sample artifacts to a `sample_artifacts.json` file.

---

## 2. Dependency Contract with `crypto_core.py` (Member 1)
Assume `crypto_core.py` in the same directory exposes:
* `PublicKeyDirectory()` with `.register_user(username, pub_key, update_trusted_fingerprint=True)`, `.tamper_registry_key(username, fake_pub_key)`, `.get_public_key(username, verify_fingerprint=True)`, `.get_public_key_hex(username)`
* `User(name, directory)` with:
  * `.private_key`, `.public_key`, `.get_public_key_hex()`, `.get_fingerprint()`, `.save_public_key_pem(filepath)`
  * `.sign_message(recipient, plaintext, shared_aes_key=None, custom_counter=None, custom_timestamp=None) -> dict`
  * `.verify_message(packet, enforce_replay_defense=True, verify_key_fingerprint=True, shared_aes_key=None, max_age_seconds=300) -> dict` (returns dict with keys: `valid`, `sender`, `recipient`, `status_code`, `reason`, `plaintext`, `encrypted`, `counter`, `timestamp`, `signature_hex_preview`)

---

## 3. Required Security Experiments to Implement
You must implement individual functions for each experiment AND a master function `run_all_experiments(export_artifacts: bool = True) -> list[dict]` that runs all of them sequentially with rich formatted output.

### Baseline Test: Normal Authentic Message Exchange
* **Function:** `exp0_baseline(alice: User, bob: User) -> dict`
* **Action:** Alice signs `"Meet me at the library at 4 PM. Bring the project notes."` and sends it to Bob. Bob verifies it with all defenses ON.
* **Expected Outcome:** `valid=True`, `status_code="SUCCESS"`. Display Alice's Public Key (hex), SHA-256 Fingerprint, Envelope JSON, Signature (Base64), and Bob's verification status.

### Experiment 1: Message Modification (Tampering in Transit)
* **Function:** `exp1_message_modification(alice: User, bob: User) -> dict`
* **Action:**
  1. Alice signs `"Transfer $100 to account #4491"`.
  2. Attacker intercepts the packet in transit (`copy.deepcopy(packet)`) and modifies 1 character in `packet["envelope"]["payload"]` to `"Transfer $900 to account #4491"` **without** generating a new signature.
  3. Also test a second sub-case: Attacker flips 1 byte in `packet["signature"]` while keeping the message unchanged.
  4. Bob attempts verification on both.
* **Expected Outcome:** Both fail with `valid=False`, `status_code="INVALID_SIGNATURE"`. Print a clear technical observation explaining how the SHA-512 hash inside Ed25519 exhibits the avalanche effect, invalidating the signature equation.

### Experiment 2: Sender Impersonation Attempt
* **Function:** `exp2_impersonation_attempt(alice: User, bob: User, directory: PublicKeyDirectory) -> dict`
* **Action:**
  1. Instantiate an attacker `mallory = User("Mallory", directory)`.
  2. Mallory wants to send `"Urgent: Send the server root password to this address"` to Bob, pretending to be Alice.
  3. Mallory signs the envelope using **Mallory's own private key**, but sets `envelope["sender"] = "Alice"` before signing (create a helper or craft the envelope signed by `mallory.private_key` with `"sender": "Alice"`).
  4. Bob receives the message and looks up **Alice's authentic public key** from `directory` to verify.
* **Expected Outcome:** Fails with `valid=False`, `status_code="INVALID_SIGNATURE"`. Explain that without Alice's private key, Mallory cannot produce a valid signature under Alice's public key due to the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

### Experiment 3: Public-Key Substitution Attack & Fingerprint Defense
* **Function:** `exp3_public_key_substitution(alice: User, bob: User, directory: PublicKeyDirectory) -> dict`
* **Action:**
  1. Attacker (`Mallory`) generates a rogue Ed25519 key pair (`mallory.private_key`, `mallory.public_key`).
  2. Mallory compromises the unauthenticated directory and replaces Alice's public key with Mallory's public key using `directory.tamper_registry_key("Alice", mallory.public_key)`.
  3. Mallory crafts an envelope with `"sender": "Alice"` and `"payload": "Approve wire transfer to offshore account"`, signing it with `mallory.private_key`.
  4. **Part A (Vulnerable System - No Public-Key Authentication):** Bob calls `bob.verify_message(forged_packet, verify_key_fingerprint=False)`. Show that Bob **incorrectly accepts** the forged message (`valid=True`!) because the signature matches the substituted key in the directory.
  5. **Part B (Defended System - Out-of-Band Trusted Fingerprint Check):** Bob calls `bob.verify_message(forged_packet, verify_key_fingerprint=True)`. Show that Bob's client detects the SHA-256 fingerprint mismatch (`valid=False`, `status_code="KEY_SUBSTITUTION_DETECTED"`).
  6. Restore Alice's real public key in `directory.register_user("Alice", alice.public_key, update_trusted_fingerprint=True)`.
* **Expected Outcome:** Clearly contrasts Part A (`ACCEPTED - VULNERABLE`) and Part B (`REJECTED - PROTECTED BY FINGERPRINT`).

### Experiment 4: Confidentiality Analysis & Optional AES-GCM Extension
* **Function:** `exp4_confidentiality_analysis(alice: User, bob: User) -> dict`
* **Action:**
  1. **Part A (Digital Signature Only):** Alice signs a confidential message `"API_SECRET_KEY=sk_live_987654321"`. An eavesdropper inspects `packet["envelope"]["payload"]` on the wire. Show that even though the signature is valid, the plaintext is 100% readable by anyone intercepting the packet.
  2. **Part B (Digital Signature + AES-256-GCM Authenticated Encryption):** Generate a 256-bit shared key (`AESGCM.generate_key(bit_length=256)`). Alice calls `alice.sign_message("Bob", "API_SECRET_KEY=sk_live_987654321", shared_aes_key=aes_key)`.
  3. Show what the eavesdropper sees on the wire (Base64 ciphertext + 12-byte nonce—plaintext is completely hidden).
  4. Show Bob calling `bob.verify_message(enc_packet, shared_aes_key=aes_key)`, verifying the Ed25519 signature AND decrypting the AES-GCM payload back to `"API_SECRET_KEY=sk_live_987654321"`.

### Experiment 5: Replay Attack & Counter/Timestamp Defense
* **Function:** `exp5_replay_attack(alice: User, bob: User) -> dict`
* **Action:**
  1. Alice sends a valid signed command to Bob: `"Pay $50 to contractor"`.
  2. Bob receives and verifies it the first time (`valid=True`).
  3. Attacker records the exact transmitted JSON packet and replays (resends) the identical packet to Bob a second time.
  4. **Part A (Without Replay Defense):** Bob verifies with `enforce_replay_defense=False`. Show that because the signature is still mathematically valid, Bob accepts the duplicate payment command (`valid=True` - Vulnerable!).
  5. **Part B (With Sequence Counter & Timestamp Defense):** Bob verifies the replayed packet with `enforce_replay_defense=True`. Show that Bob immediately rejects it (`valid=False`, `status_code="REPLAY_DETECTED"`).
  6. **Part C (Attacker Tries Incrementing Counter Without Private Key):** Attacker takes the captured packet, increments `packet["envelope"]["counter"] += 1` to bypass the replay cache, and sends it to Bob. Show that Bob rejects it with `status_code="INVALID_SIGNATURE"` because the counter is bound inside the signed canonical JSON envelope.

---

## 4. Artifact Generation & Reporting Requirements
When `run_all_experiments(export_artifacts=True)` runs:
1. Save Alice's and Bob's public keys to `artifacts/alice_public.pem` and `artifacts/bob_public.pem`.
2. Save all sample messages, envelopes, public key hex strings, fingerprints, signatures, and experimental results to `artifacts/sample_results.json` so the team can attach it directly as Deliverable #3 and #4.
3. Use the `rich` library (`Console`, `Table`, `Panel`) to print clean color-coded summary tables (Green for expected defense success, Red for demonstrated vulnerability) so Member 3 can take high-resolution screenshots for the project report.