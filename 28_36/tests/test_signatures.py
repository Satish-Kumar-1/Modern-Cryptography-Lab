"""Automated tests. Run from the project root:  python3 -m unittest -v tests.test_signatures"""
import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path

import crypto_utils as cu


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.t = Path(self._tmp.name)
        self.priv, self.pub = self.t / "priv.pem", self.t / "pub.pem"
        cu.generate_keypair(self.priv, self.pub)
        self.doc = self.t / "doc.txt"
        self.doc.write_bytes(b"Certificate of Completion\nIssued by: Team\n")
        self.sig = cu.sign_file(self.doc, self.priv, self.t / "doc.sig")

    def tearDown(self):
        self._tmp.cleanup()

    def test_original_verifies(self):
        self.assertTrue(cu.verify_file(self.doc, self.sig, self.pub).ok)

    def test_modified_document_fails(self):
        bad = self.t / "bad.txt"
        data = bytearray(self.doc.read_bytes()); data[0] ^= 1
        bad.write_bytes(bytes(data))
        self.assertFalse(cu.verify_file(bad, self.sig, self.pub).ok)

    def test_wrong_public_key_fails(self):
        p2, pub2 = self.t / "p2.pem", self.t / "pub2.pem"
        cu.generate_keypair(p2, pub2)
        self.assertFalse(cu.verify_file(self.doc, self.sig, pub2).ok)

    def test_modified_signature_fails(self):
        bad = self.t / "bad.sig"
        data = bytearray(self.sig.read_bytes()); data[5] ^= 1
        bad.write_bytes(bytes(data))
        self.assertFalse(cu.verify_file(self.doc, bad, self.pub).ok)

    def test_malformed_signature_lengths_fail_without_crash(self):
        for name, content in [("empty", b""), ("short", b"abc"), ("long", b"x" * 100)]:
            f = self.t / name
            f.write_bytes(content)
            res = cu.verify_file(self.doc, f, self.pub)
            self.assertFalse(res.ok)
            self.assertIn("Malformed", res.reason)

    def test_missing_files_are_input_errors(self):
        missing = self.t / "nope"
        with self.assertRaises(cu.InputError):
            cu.verify_file(missing, self.sig, self.pub)
        with self.assertRaises(cu.InputError):
            cu.verify_file(self.doc, missing, self.pub)
        with self.assertRaises(cu.InputError):
            cu.verify_file(self.doc, self.sig, missing)

    def test_malformed_public_key_is_input_error(self):
        junk = self.t / "junk.pem"
        junk.write_text("not a key")
        with self.assertRaises(cu.InputError):
            cu.verify_file(self.doc, self.sig, junk)

    def test_private_key_file_used_as_public_key_is_input_error(self):
        with self.assertRaises(cu.InputError):
            cu.verify_file(self.doc, self.sig, self.priv)

    def test_untrusted_substituted_key_rejected(self):
        trusted_fp = cu.fingerprint(self.pub)
        apriv, apub = self.t / "a_priv.pem", self.t / "a_pub.pem"
        cu.generate_keypair(apriv, apub)
        fake = self.t / "fake.txt"; fake.write_bytes(b"fake certificate")
        fake_sig = cu.sign_file(fake, apriv, self.t / "fake.sig")
        # Valid under the attacker's key (naive verifier is fooled)...
        self.assertTrue(cu.verify_file(fake, fake_sig, apub).ok)
        # ...but rejected when the key must match the trusted fingerprint.
        self.assertFalse(cu.verify_with_trusted_fingerprint(fake, fake_sig, apub, trusted_fp).ok)
        # The genuine bundle still passes the trusted check.
        self.assertTrue(cu.verify_with_trusted_fingerprint(self.doc, self.sig, self.pub, trusted_fp).ok)

    def test_signing_and_verifying_do_not_modify_document(self):
        before = hashlib.sha256(self.doc.read_bytes()).hexdigest()
        cu.sign_file(self.doc, self.priv, self.t / "again.sig")
        cu.verify_file(self.doc, self.sig, self.pub)
        self.assertEqual(before, hashlib.sha256(self.doc.read_bytes()).hexdigest())

    def test_signature_is_64_bytes_and_stored_separately(self):
        self.assertEqual(len(self.sig.read_bytes()), 64)
        self.assertNotEqual(self.sig, self.doc)

    def test_private_key_permissions_are_owner_only(self):
        mode = stat.S_IMODE(os.stat(self.priv).st_mode)
        self.assertEqual(mode, 0o600)

    def test_keygen_refuses_to_overwrite(self):
        with self.assertRaises(cu.InputError):
            cu.generate_keypair(self.priv, self.t / "other_pub.pem")

    def test_error_messages_do_not_leak_key_material(self):
        junk = self.t / "junk.pem"
        junk.write_text("not a key")
        try:
            cu.load_private_key(junk)
        except cu.InputError as exc:
            self.assertNotIn("not a key", str(exc))


if __name__ == "__main__":
    unittest.main()