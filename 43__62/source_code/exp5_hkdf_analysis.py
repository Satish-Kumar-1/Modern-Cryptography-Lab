from dh_common import Party, derive_key, fp, banner, step, good

banner("EXPERIMENT 5: HKDF, CONTEXT AND DOMAIN SEPARATION")
alice, bob = Party("Alice"), Party("Bob")
peer = __import__('dh_common').load_public(bob.pub)
z = alice.priv.exchange(peer)
print("Raw DH secret length:", len(z), "bytes")
print("Raw secret fingerprint:", fp(z))

step("Determinism: same secret, transcript and purpose produce the same key.")
k1 = derive_key(z, alice.pub, bob.pub, b"application-key")
k2 = derive_key(z, alice.pub, bob.pub, b"application-key")
assert k1 == k2
good("Repeated derivation produced the same key.")

step("Domain separation: derive different keys for different purposes.")
k_ab = derive_key(z, alice.pub, bob.pub, b"a2b-encryption")
k_ba = derive_key(z, alice.pub, bob.pub, b"b2a-encryption")
k_mac = derive_key(z, alice.pub, bob.pub, b"mac-key")
assert len({k_ab, k_ba, k_mac}) == 3
good("Different purpose labels produced distinct keys.")

step("Transcript binding: changing the public-value context changes the key.")
_, other_pub = __import__('dh_common').generate_keypair()
k_changed = derive_key(z, alice.pub, other_pub, b"application-key")
assert k_changed != k1
good("Changed transcript context produced a different key.")
print("Application key fingerprint:", fp(k1))
print("A-to-B key fingerprint:      ", fp(k_ab))
print("B-to-A key fingerprint:      ", fp(k_ba))
