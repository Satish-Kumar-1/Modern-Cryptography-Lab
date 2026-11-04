
import os
import json
import base64
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.exceptions import InvalidSignature, InvalidTag


# Convert bytes into printable text
def encode(data):
    return base64.b64encode(data).decode("utf-8")


# Convert Base64 text back into bytes
def decode(data):
    return base64.b64decode(data, validate=True)


# Create a consistent representation of data to sign
def signed_data(packet):
    fields = {
        "sender": packet["sender"],
        "recipient": packet["recipient"],
        "message_id": packet["message_id"],
        "nonce": packet["nonce"],
        "ciphertext": packet["ciphertext"]
    }

    return json.dumps(
        fields, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


# Create the metadata authenticated by AES-GCM
def make_aad(packet):
    fields = {
        "sender": packet["sender"],
        "recipient": packet["recipient"],
        "message_id": packet["message_id"]
    }

    return json.dumps(
        fields, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


# Create keys for the local demonstration
def create_keys():
    aes_key = AESGCM.generate_key(bit_length=256)

    alice_private = Ed25519PrivateKey.generate()
    bob_private = Ed25519PrivateKey.generate()

    private_keys = {
        "Alice": alice_private,
        "Bob": bob_private
    }

    trusted_keys = {
        "Alice": alice_private.public_key(),
        "Bob": bob_private.public_key()
    }

    return aes_key, private_keys, trusted_keys


# Encrypt and sign a message
def create_packet(sender, recipient, message, aes_key, private_keys):
    if sender not in private_keys or recipient not in private_keys:
        raise ValueError("Unknown sender or recipient.")

    if sender == recipient:
        raise ValueError("Sender and recipient must differ.")

    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message cannot be empty.")

    aes = AESGCM(aes_key)
    nonce = os.urandom(12)

    packet = {
        "sender": sender,
        "recipient": recipient,
        "message_id": str(uuid.uuid4()),
        "nonce": encode(nonce),
        "ciphertext": ""
    }

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        make_aad(packet)
    )

    packet["ciphertext"] = encode(ciphertext)

    signature = private_keys[sender].sign(signed_data(packet))
    packet["signature"] = encode(signature)

    return packet


# Verify the sender's signature
def verify_packet(packet, trusted_keys):
    required = {
        "sender", "recipient", "message_id",
        "nonce", "ciphertext", "signature"
    }

    if not isinstance(packet, dict):
        raise ValueError("Invalid packet format.")

    if not required.issubset(packet.keys()):
        raise ValueError("Packet is missing required fields.")

    sender = packet["sender"]
    recipient = packet["recipient"]
    message_id = packet["message_id"]

    if sender not in trusted_keys:
        raise ValueError("Untrusted sender.")

    if not isinstance(recipient, str) or not recipient:
        raise ValueError("Invalid recipient.")

    if sender == recipient:
        raise ValueError("Sender and recipient must differ.")

    if not isinstance(message_id, str) or not message_id:
        raise ValueError("Invalid message ID.")

    try:
        signature = decode(packet["signature"])

        trusted_keys[sender].verify(
            signature, signed_data(packet)
        )

    except (InvalidSignature, ValueError, TypeError, KeyError):
        raise ValueError("Signature verification failed.")

    return True


# Authenticate and decrypt a packet
def decrypt_packet(packet, expected_recipient, aes_key):
    if packet["recipient"] != expected_recipient:
        raise ValueError("Incorrect recipient.")

    try:
        nonce = decode(packet["nonce"])
        ciphertext = decode(packet["ciphertext"])

        if len(nonce) != 12:
            raise ValueError("Invalid nonce length.")

        plaintext = AESGCM(aes_key).decrypt(
            nonce, ciphertext, make_aad(packet)
        )

        return plaintext.decode("utf-8")

    except (InvalidTag, ValueError, TypeError, KeyError):
        raise ValueError("Decryption or authentication failed.")


# Verify, check the recipient, and decrypt
def open_packet(packet, expected_recipient, aes_key, trusted_keys):
    verify_packet(packet, trusted_keys)

    if packet["recipient"] != expected_recipient:
        raise ValueError("Incorrect recipient.")

    return decrypt_packet(packet, expected_recipient, aes_key)
