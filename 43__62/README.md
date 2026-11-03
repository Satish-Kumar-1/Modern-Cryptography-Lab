# Modern Cryptography -- Project 3

## Diffie--Hellman Key Exchange and a Man-in-the-Middle Attack

**Group folder:** `43__62`

This is the code-focused submission package. The report and presentation
have been intentionally excluded.

## Project Objectives

-   Demonstrate Diffie--Hellman key exchange between two parties.
-   Simulate a Man-in-the-Middle attack on an unauthenticated exchange.
-   Demonstrate signature-based authentication to prevent key
    substitution.
-   Derive application keys using HKDF-SHA256.
-   Protect messages using AES-256-GCM.
-   Test tampering, invalid DH values, and error handling.

## Folder Structure

``` text
43__62/
├── README.md
└── source_code/
    ├── dh_common.py
    ├── exp1_normal_exchange.py
    ├── exp2_mitm_attack.py
    ├── exp3_authenticated_exchange.py
    ├── exp4_tamper_test.py
    ├── exp5_hkdf_analysis.py
    ├── exp6_error_handling.py
    ├── logs/
    ├── requirements.txt
    ├── run_all.ps1
    └── run_all.sh
```

## Folder Contents

-   `source_code/dh_common.py` -- shared finite-field Diffie--Hellman
    helpers using RFC 3526 Group 14, public-value validation,
    HKDF-SHA256, AES-256-GCM, and Ed25519 signatures.
-   `source_code/exp1_normal_exchange.py` -- honest DH exchange.
-   `source_code/exp2_mitm_attack.py` -- unauthenticated Mallory
    man-in-the-middle simulation.
-   `source_code/exp3_authenticated_exchange.py` -- signature-based
    authentication and substitution rejection.
-   `source_code/exp4_tamper_test.py` -- AES-GCM ciphertext, tag, nonce,
    and AAD tampering checks.
-   `source_code/exp5_hkdf_analysis.py` -- HKDF determinism, purpose
    separation, and transcript binding.
-   `source_code/exp6_error_handling.py` -- invalid DH input and
    decryption error handling.
-   `source_code/requirements.txt` -- required Python package.
-   `source_code/run_all.sh` and `source_code/run_all.ps1` -- run all
    six experiments and save text logs.
-   `source_code/logs/` -- execution logs for all six experiments.

## Requirements

-   Python 3.10 or newer
-   `cryptography` Python package

## Run on Windows PowerShell / VS Code Terminal

Open the terminal in the `source_code` folder and run:

``` powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

To run one experiment:

``` powershell
python .\exp1_normal_exchange.py
```

## Run on macOS / Linux

Open a terminal in the `source_code` folder:

``` bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
chmod +x run_all.sh
./run_all.sh
```

## Expected Results

The six experiments demonstrate:

1.  Successful Diffie--Hellman key exchange with matching shared
    secrets.
2.  Successful interception and message modification by Mallory in an
    unauthenticated exchange.
3.  Detection and rejection of unauthorized key substitutions through
    signature verification.
4.  Detection of ciphertext, tag, nonce, and AAD tampering using
    AES-GCM.
5.  HKDF determinism, purpose separation, and transcript binding.
6.  Rejection of invalid DH values and handling of decryption failures.

Execution logs are stored in the `logs/` directory.

## Important Security Notes

This is an educational local simulation, not a production messaging
protocol. Trusted Ed25519 public keys are configured for the
demonstration; a real system needs a secure trust-establishment
mechanism. Never publish private keys or raw shared secrets. AES-GCM
nonces must not be reused with the same key.

Do not upload `.venv/`, `__pycache__/`, `.pyc` files, passwords, private
keys, or unrelated temporary files.
