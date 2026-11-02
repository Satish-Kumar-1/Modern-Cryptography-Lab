
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "secret.key"


def generate_key():
    # Generate a secure 256-bit AES key
    key = AESGCM.generate_key(bit_length=256)

    # Save the key in a binary file
    with open(KEY_FILE, "wb") as file:
        file.write(key)

    print("New AES-256 key generated successfully!")


def load_key():
    # Check whether the key file exists
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Secret key not found!")

    # Read and return the existing key
    with open(KEY_FILE, "rb") as file:
        key = file.read()

    if len(key) != 32:
        raise ValueError("Invalid AES-256 key!")

    return key


if __name__ == "__main__":
    if not os.path.exists(KEY_FILE):
        generate_key()
    else:
        print("Secret key already exists.")
