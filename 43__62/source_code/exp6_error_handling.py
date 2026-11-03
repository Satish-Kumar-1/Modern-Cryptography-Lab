from dh_common import (P, Q, PUB_LEN, Party, load_public, InvalidPublicValue,
                       encrypt, decrypt, InvalidTag, banner, step, good)

banner("EXPERIMENT 6: INVALID INPUT AND ERROR HANDLING")
def raw_value(n):
    return n.to_bytes(PUB_LEN, "big")

non_residue = next(n for n in range(2, 100) if pow(n, Q, P) != 1)
tests = [
    ("empty input", b""),
    ("wrong-length input", b"\x01\x02"),
    ("y = 1", raw_value(1)),
    ("y = p-1", raw_value(P - 1)),
    ("y = p", raw_value(P)),
    ("non-subgroup value", raw_value(non_residue)),
]
for label, value in tests:
    step("Testing " + label)
    try:
        load_public(value)
        raise AssertionError(label + " was unexpectedly accepted")
    except InvalidPublicValue:
        good(label + " rejected safely.")

alice, bob = Party("Alice"), Party("Bob")
ka = alice.derive(bob.pub, alice.pub, bob.pub)
kb = bob.derive(alice.pub, alice.pub, bob.pub)
blob = bytearray(encrypt(ka, b"Integrity test", b"A->B"))
blob[-1] ^= 1
step("Testing corrupted AES-GCM message.")
try:
    decrypt(kb, bytes(blob), b"A->B")
    raise AssertionError("corrupted ciphertext unexpectedly accepted")
except InvalidTag:
    good("Corrupted ciphertext rejected with InvalidTag.")
