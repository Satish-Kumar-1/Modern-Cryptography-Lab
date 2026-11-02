
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from key_manager import load_key

NONCE_SIZE = 12
TAG_SIZE = 16


def encrypt_file(input_filename, output_filename):

    # 1. Read the original file
    with open(input_filename, "rb") as file:
        plaintext = file.read()

    # 2. Load the existing secret key
    key = load_key()

    # 3. Generate a fresh random nonce
    nonce = os.urandom(NONCE_SIZE)

    # 4. Create AES-GCM object
    aesgcm = AESGCM(key)

    # 5. Encrypt the original data
    # Result contains ciphertext + authentication tag
    encrypted_data = aesgcm.encrypt(nonce, plaintext, None)

    # 6. Separate ciphertext and authentication tag
    ciphertext = encrypted_data[:-TAG_SIZE]
    tag = encrypted_data[-TAG_SIZE:]

    # 7. Store nonce + ciphertext + tag
    with open(output_filename, "wb") as file:
        file.write(nonce)
        file.write(ciphertext)
        file.write(tag)

    print("Encryption successful!")
    print("Encrypted file:", output_filename)


if __name__ == "__main__":

    input_file = input("Enter input filename: ")
    output_file = input("Enter output filename: ")

    try:
        encrypt_file(input_file, output_file)

    except FileNotFoundError as e:
        print("Error:", e)

    except Exception as e:
        print("Encryption failed:", e)
