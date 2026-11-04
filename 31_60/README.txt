SECURE MESSAGING — MINIMAL PROJECT

Windows PowerShell, from extracted folder:
  py -m venv .venv
  .venv\Scripts\python.exe -m pip install cryptography

Simple GUI (Alice/Bob demonstration):
  .venv\Scripts\python.exe main.py

Interactive terminal security experiments:
  .venv\Scripts\python.exe attack_lab.py

Existing automated test suite (includes actual local TCP transport tests):
  .venv\Scripts\python.exe test_all.py

FILES:
main.py          Small Tkinter GUI for local simulated Alice/Bob messaging.
attack_lab.py    Terminal security experiments and editable intercepted packets.
crypto_utils.py Actual AES-GCM and Ed25519 cryptography.
receiver.py     SecureReceiver: recipient/replay/signature/AES-GCM validation.
messaging.py    TCP transport helpers used by existing automated tests.
mallory_proxy.py Existing TCP proxy module (retained for tests/demos).
test_all.py     Automated crypto, nonce and network tests.

IMPORTANT:
The minimal GUI and interactive terminal attack lab are LOCAL SIMULATIONS,
not an interception of actual TCP traffic. Existing automated test_all.py
also tests TCP messaging and proxy behavior. Do not claim otherwise.

The terminal lab prints real cryptographic errors, not invented PASS outcomes.
For the isolated AES-GCM test, Ed25519 is intentionally bypassed to test
AES-GCM alone; this does not give Mallory a valid signing key.

A random 12-byte nonce is generated per message. 1000 distinct samples do not
mathematically guarantee nonce uniqueness. Replay tracking is in memory.

Keep .venv locally, but do not include it in the submitted project ZIP.
Capture screenshots from your own successful run for the final report.

MANUAL CIPHERTEXT EDITING
Run python attack_lab.py, select 1, enter a message, select edit option 1.
Copy the original Base64 ciphertext, change one character, paste the FULL string.
The terminal prints before/after values and Bob verifies the edited packet.
The real receiver rejects it at Ed25519; AES-GCM is not reached.
For isolated AES-GCM authentication failure, select main menu option 2.
