"""
dh_common.py - shared helpers for the Diffie-Hellman / MITM educational project.

All cryptographic primitives come from the maintained `cryptography` package
(OpenSSL backend).  Nothing here implements DH, HKDF, AES-GCM or Ed25519
from scratch.

  * Key agreement      : finite-field Diffie-Hellman, RFC 3526 group 14 (2048-bit MODP)
  * Key derivation     : HKDF-SHA256 (RFC 5869)
  * Encryption         : AES-256-GCM (authenticated encryption)
  * Authentication     : Ed25519 digital signatures over the key-agreement messages
"""
import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag  # re-exported
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------
# Public group parameters: RFC 3526, group 14 (2048-bit safe prime), g = 2
# --------------------------------------------------------------------------
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
G = 2
Q = (P - 1) // 2            # P is a "safe prime": Q is prime, subgroup of order Q
PUB_LEN = 256               # 2048 bits -> 256 bytes
PARAM_NUMBERS = dh.DHParameterNumbers(P, G)
PARAMETERS = PARAM_NUMBERS.parameters()

CONTEXT = b"CS-Project3 DH-MITM-demo v1"   # protocol / domain-separation label


class InvalidPublicValue(Exception):
    """Peer's key-agreement value failed validation."""


class AuthenticationError(Exception):
    """Signature on a key-agreement message failed verification."""


# --------------------------------------------------------------------------
# Diffie-Hellman
# --------------------------------------------------------------------------
def public_bytes(pub_key) -> bytes:
    return pub_key.public_numbers().y.to_bytes(PUB_LEN, "big")


def generate_keypair():
    """Return (private_key_object, public_value_bytes)."""
    priv = PARAMETERS.generate_private_key()
    return priv, public_bytes(priv.public_key())


def validate_public_value(raw: bytes) -> int:
    """Validate a received DH public value (cf. NIST SP 800-56A, partial validation
    plus subgroup-membership check).  Returns y as an int or raises."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != PUB_LEN:
        raise InvalidPublicValue(f"wrong length ({len(raw)} bytes, expected {PUB_LEN})")
    y = int.from_bytes(raw, "big")
    if not (2 <= y <= P - 2):
        raise InvalidPublicValue("value outside the range [2, p-2]")
    if pow(y, Q, P) != 1:                       # y must lie in the order-q subgroup
        raise InvalidPublicValue("value is not in the prime-order subgroup")
    return y


def load_public(raw: bytes):
    """Validate, then load the peer value as a cryptography public-key object."""
    y = validate_public_value(raw)
    try:
        return dh.DHPublicNumbers(y, PARAM_NUMBERS).public_key()
    except ValueError as exc:                    # library-level rejection
        raise InvalidPublicValue(f"library rejected value: {exc}") from exc


# --------------------------------------------------------------------------
# HKDF
# --------------------------------------------------------------------------
def derive_key(shared_secret: bytes, a_pub: bytes, b_pub: bytes,
               purpose: bytes = b"application-key", length: int = 32) -> bytes:
    """HKDF-SHA256.
    salt = SHA256(A_pub || B_pub)  -> binds the key to this exact transcript
    info = protocol label || purpose -> domain separation between key uses"""
    salt = hashlib.sha256(a_pub + b_pub).digest()
    info = CONTEXT + b"|" + purpose
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(shared_secret)


# --------------------------------------------------------------------------
# AES-GCM
# --------------------------------------------------------------------------
def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)                       # 96-bit random nonce, fresh per message
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)   # ciphertext || 16-byte tag


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 12 + 16:
        raise InvalidTag()
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)       # raises InvalidTag on any change


# --------------------------------------------------------------------------
# Ed25519 authentication of key-agreement messages
# --------------------------------------------------------------------------
def _signed_payload(role: bytes, pub: bytes) -> bytes:
    return CONTEXT + b"|kex|" + role + b"|" + pub


def sign_kex(signing_key, role: bytes, pub: bytes) -> bytes:
    return signing_key.sign(_signed_payload(role, pub))


def verify_kex(verify_key, role: bytes, pub: bytes, sig: bytes) -> None:
    try:
        verify_key.verify(sig, _signed_payload(role, pub))
    except InvalidSignature as exc:
        raise AuthenticationError("signature verification FAILED") from exc


# --------------------------------------------------------------------------
# Party (simulated endpoint)
# --------------------------------------------------------------------------
class Party:
    def __init__(self, name: str):
        self.name = name
        self.priv, self.pub = generate_keypair()
        self._secret = None
        self.key = None

    def derive(self, peer_pub_raw: bytes, a_pub: bytes, b_pub: bytes, purpose=b"application-key"):
        peer = load_public(peer_pub_raw)                 # validation happens here
        self._secret = self.priv.exchange(peer)          # raw DH shared secret (256 bytes)
        self.key = derive_key(self._secret, a_pub, b_pub, purpose)
        return self.key


# --------------------------------------------------------------------------
# Presentation helpers (log output never contains secret key material)
# --------------------------------------------------------------------------
def fp(data: bytes) -> str:
    """Short SHA-256 fingerprint, used only to compare values without revealing them."""
    return hashlib.sha256(data).hexdigest()[:16]


def banner(title: str):
    print("=" * 78)
    print(title)
    print("=" * 78)


def step(msg):  print(f"[*] {msg}")
def good(msg):  print(f"[+] {msg}")
def bad(msg):   print(f"[!] {msg}")

