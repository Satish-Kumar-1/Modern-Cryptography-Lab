import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_ID = "EDU-X25519-AKE-v1"
X25519_KEY_LENGTH = 32
ED25519_KEY_LENGTH = 32
AES_GCM_KEY_LENGTH = 32
AES_GCM_NONCE_LENGTH = 12
AES_GCM_TAG_LENGTH = 16
DEFAULT_SALT_LENGTH = 32


@dataclass(frozen=True)
class EncryptedMessage:
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    associated_data: bytes = b""


@dataclass(frozen=True)
class SignedKeyExchangeMessage:
    protocol: str
    sender: str
    recipient: str
    session_id: str
    ephemeral_public_bytes: bytes
    signature: bytes


class UntrustedIdentityError(Exception):
    pass


class ProtocolValidationError(Exception):
    pass


def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def validate_x25519_public_bytes(public_bytes: bytes) -> x25519.X25519PublicKey:
    if not isinstance(public_bytes, bytes):
        raise TypeError("X25519 public key must be provided as raw bytes.")
    if len(public_bytes) != X25519_KEY_LENGTH:
        raise ValueError(
            f"Invalid X25519 public key length: expected {X25519_KEY_LENGTH} bytes, got {len(public_bytes)}."
        )
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)


def compute_x25519_shared_secret(
    private_key: x25519.X25519PrivateKey, peer_public_bytes: bytes
) -> bytes:
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise TypeError("Invalid X25519 private key instance.")
    peer_public_key = validate_x25519_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)
    if all(byte == 0 for byte in shared_secret):
        raise ValueError("Rejected low-order X25519 shared secret.")
    return shared_secret


def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
    if length < 16:
        raise ValueError("Salt length must be at least 16 bytes.")
    return secrets.token_bytes(length)


def generate_session_id() -> str:
    return secrets.token_hex(16)


def build_hkdf_context_info(
    protocol: str,
    session_id: str,
    initiator: str,
    responder: str,
    purpose: str,
) -> bytes:
    if not all([protocol, session_id, initiator, responder, purpose]):
        raise ValueError("All HKDF context fields must be non-empty strings.")
    canonical_context = {
        "initiator": initiator,
        "protocol": protocol,
        "purpose": purpose,
        "responder": responder,
        "session_id": session_id,
    }
    serialized = json.dumps(
        canonical_context, sort_keys=True, separators=(",", ":")
    )
    return serialized.encode("utf-8")


def derive_aes_key_with_hkdf(
    shared_secret: bytes,
    salt: bytes,
    context_info: bytes,
    key_length: int = AES_GCM_KEY_LENGTH,
) -> bytes:
    if not isinstance(shared_secret, bytes) or len(shared_secret) != X25519_KEY_LENGTH:
        raise ValueError("Shared secret must be 32 bytes for HKDF derivation.")
    if not isinstance(salt, bytes) or len(salt) == 0:
        raise ValueError("Explicit non-empty salt bytes are required for HKDF.")
    if not isinstance(context_info, bytes) or len(context_info) == 0:
        raise ValueError("Explicit non-empty context_info bytes are required for HKDF.")
    if key_length != AES_GCM_KEY_LENGTH:
        raise ValueError(f"Derived AES key length must be {AES_GCM_KEY_LENGTH} bytes.")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        info=context_info,
    )
    return hkdf.derive(shared_secret)


def constant_time_compare(first_value: bytes, second_value: bytes) -> bool:
    if not isinstance(first_value, bytes) or not isinstance(second_value, bytes):
        raise TypeError("Constant-time comparison requires byte strings.")
    return hmac.compare_digest(first_value, second_value)


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_signed_key_agreement_payload(
    protocol: str,
    sender: str,
    recipient: str,
    session_id: str,
    ephemeral_public_bytes: bytes,
) -> bytes:
    validate_x25519_public_bytes(ephemeral_public_bytes)
    if not all([protocol, sender, recipient, session_id]):
        raise ValueError("All protocol envelope fields must be non-empty.")
    payload = {
        "ephemeral_public_hex": ephemeral_public_bytes.hex(),
        "protocol": protocol,
        "recipient": recipient,
        "sender": sender,
        "session_id": session_id,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return canonical_json.encode("utf-8")


def create_signed_key_exchange_message(
    signing_private_key: ed25519.Ed25519PrivateKey,
    protocol: str,
    sender: str,
    recipient: str,
    session_id: str,
    ephemeral_public_bytes: bytes,
) -> SignedKeyExchangeMessage:
    if not isinstance(signing_private_key, ed25519.Ed25519PrivateKey):
        raise TypeError("Expected an Ed25519PrivateKey for signing.")
    canonical_bytes = serialize_signed_key_agreement_payload(
        protocol=protocol,
        sender=sender,
        recipient=recipient,
        session_id=session_id,
        ephemeral_public_bytes=ephemeral_public_bytes,
    )
    signature = signing_private_key.sign(canonical_bytes)
    return SignedKeyExchangeMessage(
        protocol=protocol,
        sender=sender,
        recipient=recipient,
        session_id=session_id,
        ephemeral_public_bytes=ephemeral_public_bytes,
        signature=signature,
    )


def verify_signed_key_exchange_message(
    message: SignedKeyExchangeMessage,
    trusted_registry: Dict[str, ed25519.Ed25519PublicKey],
    expected_protocol: str,
    expected_sender: str,
    expected_recipient: str,
    expected_session_id: str,
) -> bytes:
    if message.protocol != expected_protocol:
        raise ProtocolValidationError(
            f"Protocol mismatch: expected '{expected_protocol}', got '{message.protocol}'."
        )
    if message.sender != expected_sender:
        raise ProtocolValidationError(
            f"Sender mismatch: expected '{expected_sender}', got '{message.sender}'."
        )
    if message.recipient != expected_recipient:
        raise ProtocolValidationError(
            f"Recipient mismatch: expected '{expected_recipient}', got '{message.recipient}'."
        )
    if message.session_id != expected_session_id:
        raise ProtocolValidationError(
            f"Session ID mismatch: expected '{expected_session_id}', got '{message.session_id}'."
        )
    if expected_sender not in trusted_registry:
        raise UntrustedIdentityError(
            f"Sender '{expected_sender}' is not present in the trusted public-key registry."
        )
    trusted_public_key = trusted_registry[expected_sender]
    if not isinstance(trusted_public_key, ed25519.Ed25519PublicKey):
        raise TypeError("Registry entry is not a valid Ed25519PublicKey.")
    validate_x25519_public_bytes(message.ephemeral_public_bytes)
    canonical_bytes = serialize_signed_key_agreement_payload(
        protocol=message.protocol,
        sender=message.sender,
        recipient=message.recipient,
        session_id=message.session_id,
        ephemeral_public_bytes=message.ephemeral_public_bytes,
    )
    trusted_public_key.verify(message.signature, canonical_bytes)
    return message.ephemeral_public_bytes


def encrypt_aes_gcm(
    key: bytes, plaintext: bytes, associated_data: bytes = b""
) -> EncryptedMessage:
    if not isinstance(key, bytes) or len(key) != AES_GCM_KEY_LENGTH:
        raise ValueError(f"AES-GCM key must be {AES_GCM_KEY_LENGTH} bytes.")
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")
    if not isinstance(associated_data, bytes):
        raise TypeError("Associated data must be bytes.")
    nonce = secrets.token_bytes(AES_GCM_NONCE_LENGTH)
    aesgcm = AESGCM(key)
    combined_output = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = combined_output[:-AES_GCM_TAG_LENGTH]
    tag = combined_output[-AES_GCM_TAG_LENGTH:]
    return EncryptedMessage(
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        associated_data=associated_data,
    )


def decrypt_aes_gcm(key: bytes, encrypted_message: EncryptedMessage) -> bytes:
    if not isinstance(key, bytes) or len(key) != AES_GCM_KEY_LENGTH:
        raise ValueError(f"AES-GCM key must be {AES_GCM_KEY_LENGTH} bytes.")
    if not isinstance(encrypted_message.nonce, bytes) or len(encrypted_message.nonce) != AES_GCM_NONCE_LENGTH:
        raise ValueError(f"AES-GCM nonce must be {AES_GCM_NONCE_LENGTH} bytes.")
    if not isinstance(encrypted_message.tag, bytes) or len(encrypted_message.tag) != AES_GCM_TAG_LENGTH:
        raise InvalidTag("AES-GCM authentication tag length is invalid.")
    aesgcm = AESGCM(key)
    combined_input = encrypted_message.ciphertext + encrypted_message.tag
    return aesgcm.decrypt(
        encrypted_message.nonce,
        combined_input,
        encrypted_message.associated_data,
    )


def flip_single_bit(data: bytes, byte_index: int = 0, bit_index: int = 0) -> bytes:
    if not isinstance(data, bytes) or len(data) == 0:
        raise ValueError("Data to modify must be non-empty bytes.")
    if byte_index < 0 or byte_index >= len(data):
        raise IndexError("byte_index is out of range.")
    if bit_index < 0 or bit_index > 7:
        raise ValueError("bit_index must be between 0 and 7.")
    mutable = bytearray(data)
    mutable[byte_index] ^= 1 << bit_index
    return bytes(mutable)