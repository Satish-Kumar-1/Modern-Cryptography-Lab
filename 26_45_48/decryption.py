
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from key_manager import load_key

NONCE_SIZE = 12
TAG_SIZE = 16


def decrypt_file(input_filename, output_filename):

    # 1. Read the encrypted file
    with open(input_filename, "rb") as file:
        encrypted_data = file.read()

    # 2. Check whether the file is large enough
    if len(encrypted_data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Invalid encrypted file!")

    # 3. Extract the nonce
    nonce = encrypted_data[:NONCE_SIZE]

    # 4. Extract the ciphertext
    ciphertext = encrypted_data[NONCE_SIZE:-TAG_SIZE]

    # 5. Extract the authentication tag
    tag = encrypted_data[-TAG_SIZE:]

    # 6. Load the original secret key
    key = load_key()

    # 7. Create AES-GCM object
    aesgcm = AESGCM(key)

    # 8. Combine ciphertext and tag
    encrypted_content = ciphertext + tag

    # 9. Authenticate and decrypt
    # If the key or encrypted data is incorrect,
    # AES-GCM raises InvalidTag
    plaintext = aesgcm.decrypt(
        nonce,
        encrypted_content,
        None
    )

    # 10. Save the recovered original content
    with open(output_filename, "wb") as file:
        file.write(plaintext)

    print("Decryption successful!")
    print("Decrypted file:", output_filename)


if __name__ == "__main__":

    input_file = input("Enter encrypted filename: ")
    output_file = input("Enter output filename: ")

    try:
        decrypt_file(input_file, output_file)

    except InvalidTag:
        print("Decryption failed!")
        print("Incorrect key or encrypted data has been modified.")

    except FileNotFoundError as e:
        print("Error:", e)

    except ValueError as e:
        print("Error:", e)

    except OSError as e:
        print("File error:", e)
