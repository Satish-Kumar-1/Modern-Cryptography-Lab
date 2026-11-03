from dh_common import Party, encrypt, decrypt, fp, banner, step, good

banner("EXPERIMENT 1: HONEST DIFFIE-HELLMAN EXCHANGE")
alice, bob = Party("Alice"), Party("Bob")
step("Alice and Bob exchange public DH values.")
key_a = alice.derive(bob.pub, alice.pub, bob.pub)
key_b = bob.derive(alice.pub, alice.pub, bob.pub)
print("Alice key fingerprint:", fp(key_a))
print("Bob key fingerprint:  ", fp(key_b))
assert key_a == key_b
good("Both parties independently derived the same AES key.")
message = b"Hello Bob, this is Alice."
blob = encrypt(key_a, message, b"Alice->Bob")
recovered = decrypt(key_b, blob, b"Alice->Bob")
print("Recovered message:", recovered.decode())
assert recovered == message
good("AES-GCM encryption and decryption succeeded.")
