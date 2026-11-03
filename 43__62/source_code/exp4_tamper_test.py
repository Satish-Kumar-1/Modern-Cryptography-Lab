from dh_common import Party, encrypt, decrypt, InvalidTag, banner, step, good

banner("EXPERIMENT 4: AES-GCM TAMPERING DETECTION")
alice, bob = Party("Alice"), Party("Bob")
ka = alice.derive(bob.pub, alice.pub, bob.pub)
kb = bob.derive(alice.pub, alice.pub, bob.pub)
message, aad = b"Pay 100 units", b"Alice->Bob"
blob = encrypt(ka, message, aad)
assert decrypt(kb, blob, aad) == message
good("Untampered ciphertext decrypted successfully.")

cases = []
changed = bytearray(blob); changed[12] ^= 1; cases.append(("ciphertext", bytes(changed), aad))
changed = bytearray(blob); changed[-1] ^= 1; cases.append(("authentication tag", bytes(changed), aad))
changed = bytearray(blob); changed[0] ^= 1; cases.append(("nonce", bytes(changed), aad))
cases.append(("AAD", blob, b"Alice->Mallory"))
for label, altered, altered_aad in cases:
    step(f"Testing modified {label}.")
    try:
        decrypt(kb, altered, altered_aad)
        raise AssertionError(f"Modified {label} was accepted")
    except InvalidTag:
        good(f"Modified {label} rejected (InvalidTag).")
