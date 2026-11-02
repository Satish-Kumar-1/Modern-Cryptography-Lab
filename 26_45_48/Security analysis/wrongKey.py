import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

wrong_key = AESGCM.generate_key(bit_length=256)

with open("wrong.key", "wb") as file:
    file.write(wrong_key)

print("Incorrect test key generated!")
