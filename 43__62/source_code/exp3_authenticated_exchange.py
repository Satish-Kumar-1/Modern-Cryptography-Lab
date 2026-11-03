from cryptography.hazmat.primitives.asymmetric import ed25519
from dh_common import (Party, sign_kex, verify_kex, AuthenticationError,
                       encrypt, decrypt, banner, step, good, bad)

banner("EXPERIMENT 3: AUTHENTICATED KEY EXCHANGE")
alice, bob = Party("Alice"), Party("Bob")
alice_sign = ed25519.Ed25519PrivateKey.generate()
bob_sign = ed25519.Ed25519PrivateKey.generate()
mallory_sign = ed25519.Ed25519PrivateKey.generate()
# In a real system these trusted public keys must be provisioned securely.
trusted = {b"ALICE": alice_sign.public_key(), b"BOB": bob_sign.public_key()}

sig_a = sign_kex(alice_sign, b"ALICE", alice.pub)
sig_b = sign_kex(bob_sign, b"BOB", bob.pub)
verify_kex(trusted[b"ALICE"], b"ALICE", alice.pub, sig_a)
verify_kex(trusted[b"BOB"], b"BOB", bob.pub, sig_b)
key_a = alice.derive(bob.pub, alice.pub, bob.pub)
key_b = bob.derive(alice.pub, alice.pub, bob.pub)
assert key_a == key_b
blob = encrypt(key_a, b"Authenticated hello", b"Alice->Bob")
assert decrypt(key_b, blob, b"Alice->Bob") == b"Authenticated hello"
good("Valid signed public values were accepted; authenticated message delivered.")

step("Test 1: substitute Alice's DH value but keep her original signature.")
_, substituted = Party("Mallory").priv, Party("Mallory-temp").pub
try:
    verify_kex(trusted[b"ALICE"], b"ALICE", substituted, sig_a)
    raise AssertionError("substitution unexpectedly accepted")
except AuthenticationError:
    good("Substituted DH value rejected.")

step("Test 2: Mallory signs a substituted value with her own untrusted key.")
mallory_pub = Party("Mallory").pub
mallory_sig = sign_kex(mallory_sign, b"ALICE", mallory_pub)
try:
    verify_kex(trusted[b"ALICE"], b"ALICE", mallory_pub, mallory_sig)
    raise AssertionError("untrusted signer unexpectedly accepted")
except AuthenticationError:
    good("Signature from an untrusted key rejected.")

step("Test 3: attempt role/reflection confusion.")
try:
    verify_kex(trusted[b"BOB"], b"ALICE", bob.pub, sig_b)
    raise AssertionError("wrong role unexpectedly accepted")
except AuthenticationError:
    good("Role mismatch rejected.")
