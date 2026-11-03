# Ed25519 Document Verification Tool

A lightweight Python CLI tool for generating cryptographic key pairs, signing files, and verifying file integrity using Ed25519 digital signatures (`cryptography` library).

Part of the **Modern-Cryptography-Lab** repository.

---

## Features

* **Key Pair Generation**: Securely generates Ed25519 private and public key pairs (`private_key.pem`, `public_key.pem`).
* **Document Signing**: Creates digital signatures for any file format (PDF, TXT, images, binaries, etc.).
* **Signature Verification**: Verifies whether a document's signature is valid and untampered.

---

## Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Satish-Kumar-1/Modern-Cryptography-Lab.git
cd Modern-Cryptography-Lab
```

### 2. Install Dependencies
Make sure Python 3.7+ is installed, then run:
```bash
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Generate Key Pair
Generates `private_key.pem` and `public_key.pem` in the working directory.
```bash
python document_tool.py generate-keys
```
> **Note:** Will not overwrite existing key files to prevent accidental data loss.

### 2. Sign a Document
Signs a target file using the private key and outputs the signature file.
```bash
python document_tool.py sign <path-to-document> <path-to-signature-output>
```
**Example:**
```bash
python document_tool.py sign document.pdf document.pdf.sig
```

### 3. Verify a Document
Verifies that the target file matches the signature using the public key.
```bash
python document_tool.py verify <path-to-document> <path-to-signature-file>
```
**Example:**
```bash
python document_tool.py verify document.pdf document.pdf.sig
```

---

## How to Push Your Changes

Run the following commands in your terminal to push your project files to the repository:

```bash
# 1. Add your project directory/files
git add document_tool.py requirements.txt README.md

# 2. Commit your changes
git commit -m "Add Ed25519 Document Verification Tool"

# 3. Push to the main branch
git push origin main
```

> **Security Note:** Never commit `private_key.pem` to GitHub. Add `private_key.pem` to your `.gitignore` file before pushing.