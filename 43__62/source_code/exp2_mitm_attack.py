from dh_common import Party, generate_keypair, derive_key, encrypt, decrypt, fp, banner, step, good

banner("EXPERIMENT 2: UNAUTHENTICATED MAN-IN-THE-MIDDLE")
alice, bob = Party("Alice"), Party("Bob")
mallory_a_priv, mallory_a_pub = generate_keypair()
mallory_b_priv, mallory_b_pub = generate_keypair()

step("Mallory replaces Bob's public value before it reaches Alice.")
alice_key = alice.derive(mallory_a_pub, alice.pub, mallory_a_pub)
mallory_left_secret = mallory_a_priv.exchange(__import__('dh_common').load_public(alice.pub))
mallory_left_key = derive_key(mallory_left_secret, alice.pub, mallory_a_pub)
assert alice_key == mallory_left_key

step("Mallory separately replaces Alice's public value before it reaches Bob.")
bob_key = bob.derive(mallory_b_pub, mallory_b_pub, bob.pub)
mallory_right_secret = mallory_b_priv.exchange(__import__('dh_common').load_public(bob.pub))
mallory_right_key = derive_key(mallory_right_secret, mallory_b_pub, bob.pub)
assert bob_key == mallory_right_key
print("Alice-Mallory key fingerprint:", fp(alice_key))
print("Mallory-Bob key fingerprint:  ", fp(bob_key))
assert alice_key != bob_key
good("Mallory established two different shared keys.")

original = b"Transfer 100 to account 4455"
step("Alice encrypts a message. Mallory decrypts, modifies, and re-encrypts it.")
from_alice = encrypt(alice_key, original, b"Alice->Bob")
readable = decrypt(mallory_left_key, from_alice, b"Alice->Bob")
modified = readable.replace(b"4455", b"6666")
to_bob = encrypt(mallory_right_key, modified, b"Alice->Bob")
received = decrypt(bob_key, to_bob, b"Alice->Bob")
print("Mallory read:", readable.decode())
print("Bob received:", received.decode())
assert received == b"Transfer 100 to account 6666"
good("The unauthenticated MITM attack succeeded: both encrypted hops passed AES-GCM.")
