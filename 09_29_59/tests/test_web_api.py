"""Unit and integration tests for CryptoGuard Web API Server.

Tests static file serving, in-memory cryptographic API endpoints,
and security experiment execution over HTTP.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from server import CryptoGuardHandler
from src.key_manager import KeyManager

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestWebApiServer(unittest.TestCase):
    """Test suite for server.py HTTP handler."""

    @classmethod
    def setUpClass(cls):
        # Start server on a test port
        cls.port = 8899
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), CryptoGuardHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post_json(self, endpoint: str, data: dict) -> tuple[int, dict]:
        conn = HTTPConnection("127.0.0.1", self.port)
        body = json.dumps(data).encode("utf-8")
        conn.request("POST", endpoint, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8")
        conn.close()
        return resp.status, json.loads(raw)

    def get_path(self, path: str) -> tuple[int, str, bytes]:
        conn = HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", path)
        resp = conn.getresponse()
        content_type = resp.getheader("Content-Type", "")
        data = resp.read()
        conn.close()
        return resp.status, content_type, data

    def test_serve_index_html(self):
        """Verify root path serves index.html."""
        status, ctype, data = self.get_path("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"CryptoGuard", data)

    def test_serve_static_css_and_js(self):
        """Verify static CSS and JS are served with proper MIME types."""
        status_css, ctype_css, data_css = self.get_path("/static/css/styles.css")
        self.assertEqual(status_css, 200)
        self.assertIn("text/css", ctype_css)
        self.assertIn(b"--font-family", data_css)

        status_js, ctype_js, data_js = self.get_path("/static/js/app.js")
        self.assertEqual(status_js, 200)
        self.assertIn("javascript", ctype_js)
        self.assertIn(b"CryptoGuardApp", data_js)

    def test_sample_artifacts_endpoint(self):
        """Verify sample artifacts endpoint returns authentic repository assets."""
        status, data = self.post_json("/api/sample-artifacts", {})
        self.assertEqual(status, 200)
        self.assertIn("document", data)
        self.assertIn("signature", data)
        self.assertIn("publicKey", data)
        self.assertEqual(data["document"]["name"], "sample_document.txt")

    def test_verify_authentic_document(self):
        """Verify /api/verify returns is_valid=True for authentic sample artifacts."""
        _, artifacts = self.post_json("/api/sample-artifacts", {})

        status, res = self.post_json("/api/verify", {
            "document": artifacts["document"]["contentBase64"],
            "signature": artifacts["signature"]["contentBase64"],
            "publicKey": artifacts["publicKey"]["contentBase64"],
        })
        self.assertEqual(status, 200)
        self.assertTrue(res["is_valid"])
        self.assertIn("SUCCEEDED", res["message"])
        self.assertIsNotNone(res["fingerprint"])

    def test_verify_tampered_document(self):
        """Verify /api/verify returns is_valid=False when document content is tampered."""
        _, artifacts = self.post_json("/api/sample-artifacts", {})
        tampered_bytes = base64.b64decode(artifacts["document"]["contentBase64"]) + b" [TAMPERED]"
        tampered_b64 = base64.b64encode(tampered_bytes).decode("ascii")

        status, res = self.post_json("/api/verify", {
            "document": tampered_b64,
            "signature": artifacts["signature"]["contentBase64"],
            "publicKey": artifacts["publicKey"]["contentBase64"],
        })
        self.assertEqual(status, 200)
        self.assertFalse(res["is_valid"])
        self.assertIn("FAILED", res["message"])

    def test_keygen_and_sign_lifecycle(self):
        """Test generating keys via /api/keygen and signing via /api/sign."""
        status_kg, kg_res = self.post_json("/api/keygen", {"password": "TestPassphrase2026!"})
        self.assertEqual(status_kg, 200)
        self.assertTrue(kg_res["success"])
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", kg_res["private_key"])
        self.assertIn("BEGIN PUBLIC KEY", kg_res["public_key"])

        doc_payload = base64.b64encode(b"University Degree Payload").decode("ascii")
        priv_payload = base64.b64encode(kg_res["private_key"].encode("ascii")).decode("ascii")
        pub_payload = base64.b64encode(kg_res["public_key"].encode("ascii")).decode("ascii")

        status_sign, sign_res = self.post_json("/api/sign", {
            "document": doc_payload,
            "privateKey": priv_payload,
            "password": "TestPassphrase2026!",
        })
        self.assertEqual(status_sign, 200)
        self.assertTrue(sign_res["success"])
        self.assertEqual(sign_res["size"], 64)

        # Verify the freshly signed document
        status_v, v_res = self.post_json("/api/verify", {
            "document": doc_payload,
            "signature": sign_res["signature"],
            "publicKey": pub_payload,
        })
        self.assertEqual(status_v, 200)
        self.assertTrue(v_res["is_valid"])

    def test_fingerprint_endpoint(self):
        """Test computing and matching fingerprints via /api/fingerprint."""
        _, artifacts = self.post_json("/api/sample-artifacts", {})
        pub_b64 = artifacts["publicKey"]["contentBase64"]

        # 1. Compute
        status, fp_res = self.post_json("/api/fingerprint", {"publicKey": pub_b64})
        self.assertEqual(status, 200)
        self.assertTrue(fp_res["success"])
        fp = fp_res["fingerprint"]
        self.assertTrue(fp.startswith("SHA256:"))

        # 2. Match
        _, match_res = self.post_json("/api/fingerprint", {"publicKey": pub_b64, "expected": fp})
        self.assertTrue(match_res["matches"])

        # 3. Mismatch
        _, mismatch_res = self.post_json("/api/fingerprint", {"publicKey": pub_b64, "expected": "SHA256:00:11"})
        self.assertFalse(mismatch_res["matches"])


if __name__ == "__main__":
    unittest.main()
