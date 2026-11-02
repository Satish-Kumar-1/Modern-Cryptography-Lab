# Digital Signature Verifier

A simple Streamlit app to generate Ed25519 keys, sign documents and verify signatures.

## How to run

```bash
cd digital-signature-verifier
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

The app opens at http://localhost:8501.

## How to use

1. **Key Management** – generate a key pair and download `private_key.pem` and `public_key.pem`.
2. **Sign Document** – upload a document (try `sample_files/sample_document.txt`) and your private key, then download the `.sig` file.
3. **Verify Document** – upload the document, the `.sig` file and the public key, then click Verify.
