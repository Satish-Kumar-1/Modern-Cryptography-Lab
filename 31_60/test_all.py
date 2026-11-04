
import base64
import copy
import os
import socket
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from crypto_utils import (
    create_keys,
    create_packet,
    open_packet,
    verify_packet,
    decrypt_packet,
    encode,
    decode,
    signed_data,
    make_aad,
)
from messaging import receive_packet, send_packet
from receiver import SecureReceiver


HOST = "127.0.0.1"


def start_server(handler):
    """Start a test server on an available local port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, 0))
    server.listen()

    port = server.getsockname()[1]

    def serve():
        while True:
            try:
                connection, address = server.accept()
                threading.Thread(
                    target=handler,
                    args=(connection, address),
                    daemon=True
                ).start()
            except OSError:
                break

    threading.Thread(target=serve, daemon=True).start()
    return port


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def expect_value_error(action, expected):
    try:
        action()
    except ValueError as error:
        check(str(error) == expected,
              f"Expected {expected!r}, got {str(error)!r}")
        return
    raise AssertionError(f"Expected rejection {expected!r} did not occur")


def test_crypto(aes_key, private_keys, trusted_keys):
    print("\n[Cryptography tests]")

    packet = create_packet(
        "Alice", "Bob", "Hello Bob!",
        aes_key, private_keys
    )

    message = open_packet(
        packet, "Bob", aes_key, trusted_keys
    )
    check(message == "Hello Bob!", "Normal message failed")
    print("PASS: Normal encryption and decryption")

    changed = copy.deepcopy(packet)
    changed["signature"] = "AAAA"

    expect_value_error(lambda: verify_packet(changed, trusted_keys),
                       "Signature verification failed.")
    print("PASS: Signature tampering rejected (Ed25519)")

    changed = copy.deepcopy(packet)
    data = bytearray(decode(changed["ciphertext"]))
    data[0] ^= 1
    changed["ciphertext"] = encode(bytes(data))

    # Re-sign to test AES-GCM authentication separately.
    changed["signature"] = encode(
        private_keys["Alice"].sign(signed_data(changed))
    )

    expect_value_error(lambda: decrypt_packet(changed, "Bob", aes_key),
                       "Decryption or authentication failed.")
    print("PASS: AES-GCM tampering rejected (authentication failure)")

    # Also test the raw library to establish that the underlying cause
    # is specifically InvalidTag rather than an unrelated ValueError.
    raw = decode(changed["ciphertext"])
    try:
        AESGCM(aes_key).decrypt(decode(changed["nonce"]), raw,
                                make_aad(changed))
    except InvalidTag:
        print("PASS: Raw AES-GCM raised InvalidTag")
    else:
        raise AssertionError("Raw AES-GCM accepted altered ciphertext")

    try:
        open_packet(packet, "Alice", aes_key, trusted_keys)
    except ValueError as error:
        check(str(error) == "Incorrect recipient.",
              "Unexpected wrong-recipient error")
        print("PASS: Wrong recipient rejected")
    else:
        raise AssertionError("Wrong recipient was accepted")

    changed = copy.deepcopy(packet)
    changed["message_id"] = str(uuid.uuid4())

    expect_value_error(lambda: verify_packet(changed, trusted_keys),
                       "Signature verification failed.")
    print("PASS: Metadata tampering rejected (Ed25519)")


def test_nonces(aes_key, private_keys):
    print("\n[Nonce tests]")

    nonces = set()
    total = 1000

    for i in range(total):
        packet = create_packet(
            "Alice", "Bob", "Test message " + str(i),
            aes_key, private_keys
        )
        nonce = decode(packet["nonce"])

        check(len(nonce) == 12, "Nonce is not 12 bytes")
        check(nonce not in nonces, "Nonce reuse detected")
        nonces.add(nonce)

    print("Messages generated:", total)
    print("Unique nonces:", len(nonces))
    print("PASS: No nonce collisions observed")


def test_network(aes_key, private_keys, trusted_keys):
    print("\n[Network and attack tests]")

    bob = SecureReceiver("Bob", aes_key, trusted_keys)

    def bob_handler(connection, address):
        with connection:
            try:
                packet = receive_packet(connection)
                message = bob.handle_packet(packet)
                response = "ACCEPTED: " + message
            except Exception as error:
                response = "REJECTED: " + str(error)

            connection.sendall(response.encode("utf-8"))

    bob_port = start_server(bob_handler)

    # This flag lets the same proxy forward normal or altered packets.
    proxy_state = {"tamper": False}

    def proxy_handler(connection, address):
        with connection:
            try:
                packet = receive_packet(connection)

                if proxy_state["tamper"]:
                    data = bytearray(decode(packet["ciphertext"]))
                    data[0] ^= 1
                    packet["ciphertext"] = encode(bytes(data))
                    print("Mallory modified the ciphertext.")

                response = send_packet(HOST, bob_port, packet)
                connection.sendall(response.encode("utf-8"))

            except Exception as error:
                connection.sendall(
                    ("PROXY ERROR: " + str(error)).encode("utf-8")
                )

    proxy_port = start_server(proxy_handler)
    time.sleep(0.2)

    # Test 1: Normal delivery through the proxy.
    packet = create_packet(
        "Alice", "Bob", "Hello Bob through Mallory!",
        aes_key, private_keys
    )

    response = send_packet(HOST, proxy_port, packet)
    check(
        response == "ACCEPTED: Hello Bob through Mallory!",
        "Normal proxy delivery failed: " + response
    )
    print("PASS: Proxy forwarding accepted")

    # Test 2: Replay the exact same packet.
    response = send_packet(HOST, proxy_port, packet)
    check(
        response == "REJECTED: Replay detected.",
        "Replay was not rejected: " + response
    )
    print("PASS: Replay rejected")

    # Test 3: Modify a fresh packet while it passes through Mallory.
    packet = create_packet(
        "Alice", "Bob", "This message will be tampered with!",
        aes_key, private_keys
    )

    proxy_state["tamper"] = True
    response = send_packet(HOST, proxy_port, packet)
    proxy_state["tamper"] = False

    check(
        response == "REJECTED: Signature verification failed.",
        "Tampered packet was not rejected: " + response
    )
    print("PASS: Proxy ciphertext tampering rejected")

    # Test 4: Mallory signs a packet using an untrusted key.
    attacker_private = Ed25519PrivateKey.generate()

    packet = {
        "sender": "Mallory",
        "recipient": "Bob",
        "message_id": str(uuid.uuid4()),
        "nonce": encode(os.urandom(12)),
        "ciphertext": "",
    }

    ciphertext = AESGCM(aes_key).encrypt(
        base64.b64decode(packet["nonce"]),
        b"Impersonating Alice",
        make_aad(packet)
    )
    packet["ciphertext"] = encode(ciphertext)
    packet["signature"] = encode(
        attacker_private.sign(signed_data(packet))
    )

    response = send_packet(HOST, proxy_port, packet)
    check(
        response == "REJECTED: Untrusted sender.",
        "Untrusted sender was not rejected: " + response
    )
    print("PASS: Sender impersonation rejected")


def main():
    print("=" * 55)
    print("SECURE MESSAGING - COMPLETE TEST SUITE")
    print("=" * 55)

    aes_key, private_keys, trusted_keys = create_keys()

    tests = [
        ("Cryptography and tampering",
         lambda: test_crypto(aes_key, private_keys, trusted_keys)),
        ("Nonce uniqueness",
         lambda: test_nonces(aes_key, private_keys)),
        ("Network security",
         lambda: test_network(aes_key, private_keys, trusted_keys)),
    ]

    passed = []

    for name, test in tests:
        print("\n" + "-" * 55)
        print("RUNNING:", name)

        try:
            test()
            passed.append((name, True))
            print("PASSED:", name)
        except Exception as error:
            passed.append((name, False))
            print("FAILED:", name)
            print("Reason:", error)
            break

    print("\n" + "=" * 55)
    print("FINAL TEST SUMMARY")
    print("=" * 55)

    for name, result in passed:
        print(("PASS" if result else "FAIL") + ": " + name)

    if len(passed) == len(tests) and all(
        result for name, result in passed
    ):
        print("\nALL TEST GROUPS PASSED!")
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
