#!/usr/bin/env python3
"""
Cryptographic Operations Tests for TAC Protocol Python SDK

Tests key management, algorithm selection, and cryptographic primitives.
"""

import asyncio
import os
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACCryptoError, TACValidationError
from sender import TACSender
from utils import get_algorithm_for_key, get_key_type


class TestKeyManagement(unittest.TestCase):
    """Test key management functionality"""

    def test_rsa_2048_keys(self):
        """Test RSA 2048-bit key support"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        sender = TACSender(domain="test.com", private_key=private_key)
        self.assertEqual(sender.domain, "test.com")
        self.assertEqual(get_key_type(private_key), "RSA")

    def test_rsa_3072_keys(self):
        """Test RSA 3072-bit key support"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

        sender = TACSender(domain="test.com", private_key=private_key)
        self.assertEqual(get_key_type(private_key), "RSA")
        self.assertIsNotNone(sender)  # Verify sender was created successfully

    def test_rsa_4096_keys(self):
        """Test RSA 4096-bit key support"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

        sender = TACSender(domain="test.com", private_key=private_key)
        self.assertEqual(get_key_type(private_key), "RSA")
        self.assertIsNotNone(sender)  # Verify sender was created successfully



class TestInvalidKeys(unittest.TestCase):
    """Test handling of invalid keys"""

    def test_reject_unsupported_key_types(self):
        """Test rejection of unsupported key types"""
        with self.assertRaises(TACValidationError):
            TACSender(domain="test.com", private_key=None)

    def test_handle_invalid_pem_strings(self):
        """Test handling of invalid PEM strings"""
        with self.assertRaises((TACCryptoError, ValueError)):
            TACSender(domain="test.com", private_key="invalid-pem")

    def test_handle_empty_keys(self):
        """Test handling of empty/null keys"""
        with self.assertRaises(TACValidationError):
            TACSender(domain="test.com", private_key=None)


class TestKeyIDGeneration(unittest.TestCase):
    """Test key ID generation"""

    def test_consistent_key_ids(self):
        """Test that key IDs are generated consistently"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        sender = TACSender(domain="test.com", private_key=private_key)

        key_id1 = sender.generate_key_id()
        key_id2 = sender.generate_key_id()

        self.assertEqual(key_id1, key_id2)

    def test_different_keys_different_ids(self):
        """Test that different keys generate different IDs"""
        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        sender1 = TACSender(domain="test.com", private_key=private_key1)
        sender2 = TACSender(domain="test.com", private_key=private_key2)

        key_id1 = sender1.generate_key_id()
        key_id2 = sender2.generate_key_id()

        self.assertNotEqual(key_id1, key_id2)

    def test_key_id_without_manual_public_key(self):
        """Test key ID generation without requiring manual public key"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        sender = TACSender(domain="test.com", private_key=private_key)
        key_id = sender.generate_key_id()

        self.assertIsNotNone(key_id)
        self.assertIsInstance(key_id, str)
        self.assertGreater(len(key_id), 0)


class TestJWKExport(unittest.TestCase):
    """Test JWK export functionality"""

    def test_export_rsa_public_key_as_jwk(self):
        """Test exporting RSA public key as JWK"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        sender = TACSender(domain="test.com", private_key=private_key)

        async def run_test():
            jwk = await sender.get_public_jwk()
            self.assertEqual(jwk["kty"], "RSA")
            self.assertEqual(jwk["alg"], "RS256")
            self.assertIn("kid", jwk)
            self.assertIn("n", jwk)
            self.assertIn("e", jwk)

        asyncio.run(run_test())

    def test_include_key_id_in_exported_jwk(self):
        """Test that key ID is included in exported JWK"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        sender = TACSender(domain="test.com", private_key=private_key)

        async def run_test():
            jwk = await sender.get_public_jwk()
            self.assertIn("kid", jwk)
            self.assertIsInstance(jwk["kid"], str)
            self.assertGreater(len(jwk["kid"]), 0)

        asyncio.run(run_test())


class TestAlgorithmSelection(unittest.TestCase):
    """Test algorithm selection"""

    def test_correct_signing_algorithm_for_rsa(self):
        """Test correct signing algorithm selection for RSA keys"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        algorithm = get_algorithm_for_key(private_key, "sig")
        self.assertEqual(algorithm, "RS256")



class TestStringKeySupport(unittest.TestCase):
    """Test support for string-encoded keys"""

    def test_pem_encoded_rsa_private_keys(self):
        """Test support for PEM-encoded RSA private keys"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        pem_string = pem_bytes.decode("utf-8")

        sender = TACSender(domain="test.com", private_key=pem_string)
        self.assertEqual(sender.domain, "test.com")

    def test_handle_malformed_pem_keys_gracefully(self):
        """Test handling of malformed PEM keys"""
        malformed_pem = "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"

        with self.assertRaises((TACCryptoError, ValueError)):
            TACSender(domain="test.com", private_key=malformed_pem)


if __name__ == "__main__":
    unittest.main()
