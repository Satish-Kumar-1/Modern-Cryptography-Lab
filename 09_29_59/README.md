# Digital Signature-Based Document Verification System

> **A modern standalone desktop application built with Electron, TypeScript, JavaScript, HTML5, CSS3, Shell, Batchfile, PowerShell, and Python for Ed25519 digital signatures, tamper detection, and cryptographic trust validation with Drag-and-Drop logic and Vertical Tabs.**

[![Platform](https://img.shields.io/badge/Platform-Electron%20Desktop-blueviolet.svg)](#)
[![Algorithm](https://img.shields.io/badge/Algorithm-Ed25519%20(RFC%208032)-blue.svg)](#)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](#)

---

## 📌 Project Overview

This project implements **Digital Signature-Based Document Verification** for the University Cryptography curriculum.

The core objective is to allow an author to digitally sign a document using the **Ed25519** scheme and allow any third-party verifier to independently verify:
1. **Document Integrity:** Confirmation that not a single byte, space, or character has been modified.
2. **Signature Authenticity:** Confirmation that the detached signature was produced by the holder of the corresponding Ed25519 private key.
3. **Public-Key Trust:** Verification of the public key's fingerprint against an authenticated reference, distinguishing mathematical validity from real-world signer identity.

---

## 🏗️ Repository Architecture

```
Crypto-Project/
├── .gitignore                      # Excludes private keys, caches, virtual environments
├── requirements.txt                # Python cryptographic dependencies (cryptography, pytest)
├── package.json                    # Electron & TypeScript project manifest
├── tsconfig.json                   # Web TypeScript compiler configuration
├── tsconfig.electron.json          # Electron TypeScript compiler configuration
├── start.ps1                       # [PowerShell] Native PowerShell 1-click desktop launcher
├── start.bat                       # [Batchfile] Windows 1-click desktop launcher
├── start.sh                        # [Shell] Linux/macOS 1-click desktop launcher
├── server.py                       # [Python] In-memory cryptographic engine & backend service
├── README.md                       # Project documentation & execution guide
│
├── electron/                       # Electron Desktop Application Source (TypeScript)
│   ├── main.ts                     # Main process (window manager & background backend orchestrator)
│   └── preload.ts                  # Secure preload bridge exposing window controls
│
├── dist-electron/                  # Compiled Electron Main & Preload JavaScript
│   ├── main.js
│   └── preload.js
│
├── web/                            # Desktop UI Layer (TypeScript / JS / HTML / CSS)
│   ├── index.html                  # Semantic desktop shell with Vertical Tabs & Dropzones
│   ├── static/
│   │   ├── css/
│   │   │   └── styles.css          # Modern glassmorphic styles, animations & themes
│   │   └── js/
│   │       ├── api.js              # Native HTTP API client module
│   │       ├── dropzone.js         # Interactive drag-and-drop file manager
│   │       └── app.js              # App controller & dynamic UI renderer
│   └── src/
│       ├── types.ts                # Strong TypeScript interfaces
│       ├── api.ts                  # Strongly typed API client
│       ├── dropzone.ts             # Drag-and-drop manager class
│       └── app.ts                  # Main UI orchestrator
│
├── src/                            # Core Cryptographic Engine (RFC 8032 Ed25519)
│   ├── __init__.py                 # Package declaration and public API exports
│   ├── key_manager.py              # Ed25519 key generation, PEM serialization & security
│   ├── document_signer.py          # Detached document signing (exact byte preservation)
│   ├── signature_verifier.py       # Safe signature verification & error handling
│   ├── key_fingerprint.py          # Canonical public-key SHA-256 fingerprinting
│   └── main.py                     # CLI application and workflow orchestrator
│
├── tests/                          # Automated test suite (unittest / pytest compatible)
│   ├── __init__.py
│   ├── test_key_generation.py      # Tests key generation, serialization, passphrase protection
│   ├── test_sign_verify.py         # Tests signing, verification, and tamper detection
│   ├── test_cli.py                 # End-to-end CLI command and workflow tests
│   └── test_web_api.py             # In-memory API and static file serving tests
│
├── sample_data/                    # Sample documents for verification
│   └── sample_document.txt         # Synthetic university academic credential
│
├── artifacts/                      # Public submission deliverables (Requirement 8 compliant)
│   ├── README.md                   # Explanation of artifacts & private key exclusion
│   ├── signer_public_key.pem       # Authentic public key (SPKI PEM format)
│   └── sample_document.sig         # 64-byte detached digital signature of sample_document.txt
│
└── docs/                           # Technical documentation & security analysis
    ├── cryptographic_architecture.md # Mathematical basis, threat model & API spec
    └── experiments.md              # Security analysis & theoretical observations
```

---

## 🚀 Launch the Electron Desktop Application

Launch the native desktop application with **Vertical Navigation Tabs** and **Drag-and-Drop Dropzones** (zero hardcoded paths):

### From PowerShell:
```powershell
.\start.ps1
# or: npm start
```

### From Windows Command Prompt:
```cmd
start.bat
```

### From Linux / macOS:
```bash
chmod +x start.sh
./start.sh
```

---

## 🧪 Run Automated Tests
All 32 tests use Python's built-in `unittest` runner and are also fully compatible with `pytest`:
```bash
python -m unittest discover tests -v
```

---

## 🖥️ Desktop Application Features

1. **Standalone Electron Window:**
   * Runs in its own dedicated, native desktop window (no browser tabs, no URL bar, native system controls).
2. **Vertical Navigation Tabs:**
   * Left-hand sidebar with 4 tabs: **Verify Document**, **Sign Document**, **Generate Keys**, and **Key Fingerprint**.
3. **Drag-and-Drop Logic:**
   * Interactive dropzones for documents, detached `.sig` signatures, and `.pem` keys with dragover animations, file previews, and instant byte parsing.
4. **Zero Hardcoded Paths:**
   * All files are read in-memory directly in the client and transmitted as Base64 payloads to the in-memory cryptographic core.
5. **Document Verification:**
   * Instant color-coded badges: **Green** for authentic and unmodified documents; **Red** for tampered files, invalid keys, or corrupted signatures.
   * Auto-extracts the signer's public key fingerprint.

---

## 💻 Command-Line Interface (CLI)

The CLI orchestrator in `src/main.py` is preserved for scripting:

```bash
python -m src.main verify
python -m src.main keygen
python -m src.main sign
python -m src.main fingerprint
python -m src.main all
```

---

## 🔒 Security & Key Management (Requirement 8)

* **Private Key Protection:** In strict compliance with assignment guidelines, **private keys are never committed to this repository**.
* `.gitignore` prevents inadvertent commits of private keys (`*.key`, `*.priv`, `*private*`, `*.pkcs8`).
* The submission includes only the **sample document**, the **detached signature**, and the **public key** needed for independent verification.

---

## 📄 License
This project is developed for educational and academic assessment purposes.
