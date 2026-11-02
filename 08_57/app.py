"""Streamlit user interface. It only collects input and shows results;
all cryptographic work happens in the modules/ package."""

import os
from pathlib import Path

import streamlit as st

from modules.document_handler import describe_document, load_document_from_upload
from modules.fingerprint_service import compute_fingerprint, fingerprints_match, format_fingerprint
from modules.key_manager import (generate_key_pair, load_private_key, load_public_key, private_key_to_pem,
                                 public_key_from_private, public_key_to_pem)
from modules.signing_service import sign_document
from modules.validation import InputError, validate_signature_bytes
from modules.verification_service import ERROR, VALID, verify_document
from utils.file_utils import read_upload

DEBUG_MODE = os.environ.get("SIGNER_DEBUG") == "1"   # set SIGNER_DEBUG=1 to see technical details
SAMPLE_PATH = Path(__file__).parent / "sample_files" / "sample_document.txt"
PAGES = ["Key Management", "Sign Document", "Verify Document"]

st.set_page_config(page_title="Ed25519 Document Verifier", page_icon="🔏", layout="centered")
st.markdown("""
<style>
.block-container {max-width: 860px; padding-top: 2rem;}
.hero {padding: 1.1rem 1.4rem; border-radius: 12px; margin-bottom: 1.2rem;
       background: linear-gradient(135deg, #0f2a43, #1f4e79); color: #fff;}
.hero h1 {color: #fff; font-size: 1.7rem; margin: 0 0 .2rem 0; padding: 0;}
.hero p {margin: 0; opacity: .85;}
</style>
<div class="hero"><h1>🔏 Ed25519 Document Verifier</h1>
<p>Generate keys, sign documents and verify them.</p></div>
""", unsafe_allow_html=True)


# ----------------------------------------------------------------- shared helpers
def show_fingerprint(public_key, label: str = "Public key fingerprint (SHA-256)") -> str:
    fingerprint = format_fingerprint(compute_fingerprint(public_key))
    st.markdown(f"**{label}**")
    st.code(fingerprint, language=None)
    return fingerprint


def show_unexpected_error(exc: Exception) -> None:
    st.error("Something unexpected went wrong. No result was produced. Please check your files and try again.")
    if DEBUG_MODE:
        st.exception(exc)


# ----------------------------------------------------------------- pages
def page_key_management() -> None:
    st.header("Key Management")
    st.warning("**Your private key must never be shared.** Anyone who has it can sign documents as you. "
               "Only the public key is meant to be given to others.")

    password = st.text_input("Optional password to encrypt the private key file", type="password",
                             help="Without a password, the private key file is saved unencrypted. The password is "
                                  "used once to encrypt the file and is never stored.")
    if st.button("Generate Key Pair", type="primary"):
        private_key, public_key = generate_key_pair()
        st.session_state["keys"] = {
            "private_pem": private_key_to_pem(private_key, password or None),
            "public_pem": public_key_to_pem(public_key),
            "public_key": public_key,
            "encrypted": bool(password),
        }

    keys = st.session_state.get("keys")
    if not keys:
        st.info("Click **Generate Key Pair** to create a new Ed25519 key pair.")
        return

    st.success("Key pair generated.")
    if not keys["encrypted"]:
        st.warning("This private key file is NOT password-protected. Keep it somewhere safe.")
    col_private, col_public = st.columns(2)
    with col_private:
        st.markdown("##### 🔴 Private key (secret)")
        st.caption("Used to SIGN. Never share, never upload to a public place.")
        st.download_button("Download private key", keys["private_pem"], "private_key.pem", "application/x-pem-file")
    with col_public:
        st.markdown("##### 🟢 Public key (shareable)")
        st.caption("Used to VERIFY. Give this to anyone who needs to check your signatures.")
        st.download_button("Download public key", keys["public_pem"], "public_key.pem", "application/x-pem-file")
    st.markdown("**Public key**")
    st.code(keys["public_pem"].decode(), language=None)
    show_fingerprint(keys["public_key"])
    st.caption("Share this fingerprint through a separate, trusted channel (e.g. a phone call) so others can confirm "
               "that your public key is really yours.")


def page_sign() -> None:
    st.header("Sign Document")
    st.download_button("Download a sample document to try", SAMPLE_PATH.read_bytes(), "sample_document.txt",
                       help="A small certificate you can sign.")
    document_file = st.file_uploader("1. Document to sign (any file; its exact bytes are signed)", key="sign_doc")
    key_file = st.file_uploader("2. Your private key (.pem)", key="sign_key")
    password = st.text_input("Private key password (only if the key is encrypted)", type="password")

    if st.button("Sign Document", type="primary"):
        try:
            document = load_document_from_upload(document_file)
            private_key = load_private_key(read_upload(key_file, "The private key file"), password or None)
            signature = sign_document(document, private_key)
            public_key = public_key_from_private(private_key)
            st.session_state["signed"] = {
                "name": document_file.name, "signature": signature, "info": describe_document(document),
                "public_pem": public_key_to_pem(public_key), "public_key": public_key,
            }
        except InputError as exc:
            st.session_state.pop("signed", None)
            st.error(str(exc))
        except Exception as exc:
            st.session_state.pop("signed", None)
            show_unexpected_error(exc)

    result = st.session_state.get("signed")
    if result:
        st.success(f"✅ Document '{result['name']}' signed successfully.")
        st.markdown("**Signing information**")
        st.write(f"- Document size: {result['info']['size_bytes']} bytes")
        st.write(f"- Document SHA-256 (for reference only; the signature is not just a hash): `{result['info']['sha256']}`")
        st.write(f"- Signature: {len(result['signature'])} bytes (Ed25519)")
        st.code(result["signature"].hex(), language=None)
        show_fingerprint(result["public_key"], "Signer's public key fingerprint")
        col_a, col_b = st.columns(2)
        col_a.download_button("Download signature", result["signature"], f"{result['name']}.sig")
        col_b.download_button("Download matching public key", result["public_pem"], "public_key.pem")
        st.caption("The original document is unchanged. Send the document, the signature and the public key "
                   "(or just the public key's fingerprint via a trusted channel) to the verifier.")


def page_verify() -> None:
    st.header("Verify Document")
    document_file = st.file_uploader("1. Document (original or possibly modified)", key="ver_doc")
    signature_file = st.file_uploader("2. Signature file (.sig)", key="ver_sig")
    key_file = st.file_uploader("3. Public key (.pem)", key="ver_key")
    st.markdown("**Optional: trusted fingerprint**")
    trusted_text = st.text_input("Fingerprint of the signer's key, obtained from an independent trusted channel",
                                 placeholder="AB:CD:EF:... (64 hex characters)")

    if not st.button("Verify", type="primary"):
        return
    missing = [name for name, f in [("document", document_file), ("signature", signature_file),
                                    ("public key", key_file)] if f is None]
    if missing:
        st.warning("Please upload the missing item(s): " + ", ".join(missing) + ".")
        return

    try:
        document = load_document_from_upload(document_file)
        signature = validate_signature_bytes(read_upload(signature_file, "The signature file"))
        public_key = load_public_key(read_upload(key_file, "The public key file"))
    except InputError as exc:
        st.error(str(exc))
        return
    except Exception as exc:
        show_unexpected_error(exc)
        return

    result = verify_document(document, signature, public_key)
    if result.status == VALID:
        st.success("✅ **VALID SIGNATURE**\n\n" + result.message)
    elif result.status == ERROR:
        st.warning("⚠️ **Verification could not be completed**\n\n" + result.message)
        if DEBUG_MODE and result.technical_detail:
            st.code(result.technical_detail)
    else:
        st.error("❌ **INVALID SIGNATURE**\n\n" + result.message)

    st.divider()
    st.subheader("Is this really the signer's key?")
    fingerprint = show_fingerprint(public_key, "Fingerprint of the supplied public key (SHA-256)")
    if not trusted_text.strip():
        st.info("No trusted fingerprint entered. Even a valid signature only proves that the holder of THIS key "
                "signed the document. It does not prove who that person is.")
        return
    try:
        matches = fingerprints_match(fingerprint, trusted_text)
    except InputError as exc:
        st.warning(str(exc))
        return
    if matches:
        st.success("🔑 The supplied key MATCHES your trusted fingerprint.")
        if result.is_valid:
            st.success("Valid signature AND trusted key: the document was signed by the holder of the key you trust.")
    else:
        st.error("🚫 The supplied key does NOT match your trusted fingerprint. Do not trust this key, "
                 "even if the signature is mathematically valid.")


page = st.sidebar.radio("Navigation", PAGES)
st.sidebar.caption("Educational project. Not a production security tool.")
{"Key Management": page_key_management, "Sign Document": page_sign, "Verify Document": page_verify}[page]()
