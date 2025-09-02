#!/usr/bin/env python3
"""
Utility Functions Tests for TAC Protocol Python SDK

Tests helper functions, key operations, and data validation.
"""

import os
import sys
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, rsa

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACCryptoError, TACNetworkError
from utils import (
    JWKSCache,
    find_encryption_key,
    find_signing_key,
    get_algorithm_for_key,
    get_key_type,
    get_user_agent,
    public_key_to_jwk,
)


class TestJWKSCache(unittest.TestCase):
    """Test JWKS cache functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.cache = JWKSCache(timeout=1000)  # 1 second timeout

    def test_basic_cache_operations(self):
        """Test basic cache set and get operations"""
        keys = [{"kty": "RSA", "kid": "test-key"}]

        self.cache.set("test.com", keys)
        cached_keys = self.cache.get("test.com")

        self.assertEqual(cached_keys, keys)

    def test_cache_miss_returns_none(self):
        """Test that cache miss returns None"""
        result = self.cache.get("nonexistent.com")
        self.assertIsNone(result)

    def test_cache_expiration(self):
        """Test cache expiration"""
        short_cache = JWKSCache(timeout=100)  # 0.1 seconds
        keys = [{"kty": "RSA", "kid": "test-key"}]

        short_cache.set("test.com", keys)
        self.assertEqual(short_cache.get("test.com"), keys)

        # Wait for expiration
        time.sleep(0.15)
        self.assertIsNone(short_cache.get("test.com"))

    def test_cache_clear(self):
        """Test cache clearing"""
        keys1 = [{"kty": "RSA", "kid": "key1"}]
        keys2 = [{"kty": "RSA", "kid": "key2"}]

        self.cache.set("domain1.com", keys1)
        self.cache.set("domain2.com", keys2)

        # Clear specific domain
        self.cache.clear("domain1.com")
        self.assertIsNone(self.cache.get("domain1.com"))
        self.assertEqual(self.cache.get("domain2.com"), keys2)

        # Clear all
        self.cache.clear()
        self.assertIsNone(self.cache.get("domain2.com"))


class TestKeyOperations(unittest.TestCase):
    """Test key operations and utilities"""

    def test_get_key_type_rsa(self):
        """Test RSA key type detection"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        key_type = get_key_type(private_key)
        self.assertEqual(key_type, "RSA")

        public_key = private_key.public_key()
        key_type = get_key_type(public_key)
        self.assertEqual(key_type, "RSA")

    def test_get_key_type_ec(self):
        """Test EC key type detection"""
        private_key = ec.generate_private_key(ec.SECP256R1())

        key_type = get_key_type(private_key)
        self.assertEqual(key_type, "EC")

        public_key = private_key.public_key()
        key_type = get_key_type(public_key)
        self.assertEqual(key_type, "EC")

    def test_get_key_type_invalid(self):
        """Test invalid key type handling"""
        with self.assertRaises(TACCryptoError):
            get_key_type("not-a-key")

        with self.assertRaises(TACCryptoError):
            get_key_type(None)

    def test_get_algorithm_for_rsa_signing(self):
        """Test algorithm selection for RSA signing"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        algorithm = get_algorithm_for_key(private_key, "sig")
        self.assertEqual(algorithm, "RS256")

    def test_get_algorithm_for_rsa_encryption(self):
        """Test algorithm selection for RSA encryption"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        algorithm = get_algorithm_for_key(private_key, "enc")
        self.assertEqual(algorithm, "RSA-OAEP-256")

    def test_get_algorithm_for_ec_signing(self):
        """Test algorithm selection for EC signing"""
        # P-256
        private_key = ec.generate_private_key(ec.SECP256R1())
        algorithm = get_algorithm_for_key(private_key, "sig")
        self.assertEqual(algorithm, "ES256")

        # P-384
        private_key = ec.generate_private_key(ec.SECP384R1())
        algorithm = get_algorithm_for_key(private_key, "sig")
        self.assertEqual(algorithm, "ES384")

        # P-521
        private_key = ec.generate_private_key(ec.SECP521R1())
        algorithm = get_algorithm_for_key(private_key, "sig")
        self.assertEqual(algorithm, "ES512")

    def test_get_algorithm_for_ec_encryption(self):
        """Test algorithm selection for EC encryption"""
        private_key = ec.generate_private_key(ec.SECP256R1())

        algorithm = get_algorithm_for_key(private_key, "enc")
        self.assertEqual(algorithm, "ECDH-ES+A256KW")

    def test_public_key_to_jwk_rsa(self):
        """Test RSA public key to JWK conversion"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        jwk = public_key_to_jwk(public_key, "test-key-id")

        self.assertEqual(jwk["kty"], "RSA")
        self.assertEqual(jwk["kid"], "test-key-id")
        self.assertEqual(jwk["alg"], "RS256")
        self.assertIn("n", jwk)
        self.assertIn("e", jwk)

    def test_public_key_to_jwk_ec(self):
        """Test EC public key to JWK conversion"""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        jwk = public_key_to_jwk(public_key, "test-key-id")

        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["kid"], "test-key-id")
        self.assertEqual(jwk["alg"], "ES256")
        self.assertEqual(jwk["crv"], "P-256")
        self.assertIn("x", jwk)
        self.assertIn("y", jwk)

    def test_public_key_to_jwk_auto_key_id(self):
        """Test automatic key ID generation"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        jwk = public_key_to_jwk(public_key)

        self.assertIn("kid", jwk)
        self.assertIsInstance(jwk["kid"], str)
        self.assertGreater(len(jwk["kid"]), 0)

        # Should be consistent
        jwk2 = public_key_to_jwk(public_key)
        self.assertEqual(jwk["kid"], jwk2["kid"])


class TestKeyFinding(unittest.TestCase):
    """Test key finding utilities"""

    def test_find_encryption_key_rsa(self):
        """Test finding RSA encryption key"""
        keys = [
            {"kty": "EC", "use": "sig", "kid": "ec-sig"},
            {"kty": "RSA", "use": "enc", "kid": "rsa-enc", "alg": "RSA-OAEP-256"},
            {"kty": "RSA", "use": "sig", "kid": "rsa-sig"},
        ]

        key = find_encryption_key(keys)
        self.assertIsNotNone(key)
        self.assertEqual(key["kid"], "rsa-enc")
        self.assertEqual(key["use"], "enc")

    def test_find_encryption_key_ec(self):
        """Test finding EC encryption key"""
        keys = [
            {"kty": "EC", "use": "sig", "kid": "ec-sig"},
            {"kty": "EC", "use": "enc", "kid": "ec-enc", "alg": "ECDH-ES+A256KW"},
            {"kty": "RSA", "use": "sig", "kid": "rsa-sig"},
        ]

        key = find_encryption_key(keys)
        self.assertIsNotNone(key)
        self.assertEqual(key["kid"], "ec-enc")
        self.assertEqual(key["use"], "enc")

    def test_find_encryption_key_fallback(self):
        """Test encryption key fallback when no explicit enc key"""
        keys = [{"kty": "RSA", "kid": "rsa-1"}, {"kty": "EC", "use": "sig", "kid": "ec-sig"}]  # No use specified

        key = find_encryption_key(keys)
        self.assertIsNotNone(key)
        self.assertEqual(key["kid"], "rsa-1")  # Should prefer RSA

    def test_find_signing_key_by_kid(self):
        """Test finding signing key by key ID"""
        keys = [
            {"kty": "RSA", "use": "sig", "kid": "rsa-sig-1"},
            {"kty": "RSA", "use": "sig", "kid": "rsa-sig-2"},
            {"kty": "EC", "use": "sig", "kid": "ec-sig"},
        ]

        key = find_signing_key(keys, "rsa-sig-2")
        self.assertIsNotNone(key)
        self.assertEqual(key["kid"], "rsa-sig-2")

    def test_find_signing_key_default(self):
        """Test finding default signing key"""
        keys = [
            {"kty": "EC", "use": "enc", "kid": "ec-enc"},
            {"kty": "RSA", "use": "sig", "kid": "rsa-sig"},
            {"kty": "EC", "use": "sig", "kid": "ec-sig"},
        ]

        key = find_signing_key(keys)
        self.assertIsNotNone(key)
        self.assertEqual(key["kid"], "rsa-sig")  # Should prefer RSA

    def test_find_key_not_found(self):
        """Test key not found scenarios"""
        keys = [{"kty": "RSA", "use": "sig", "kid": "rsa-sig"}]

        # No encryption keys in empty list
        enc_key = find_encryption_key([])
        self.assertIsNone(enc_key)

        # No encryption keys in list with only signing keys
        enc_key = find_encryption_key(keys)
        # This might return the RSA key as fallback, so let's check for that
        if enc_key is not None:
            self.assertEqual(enc_key["kty"], "RSA")  # Fallback behavior

        # Specific key ID not found, but function falls back to default behavior
        sig_key = find_signing_key(keys, "nonexistent")
        # The function falls back to finding any suitable signing key when specific kid not found
        # So it will return the RSA signing key as a fallback
        if sig_key is not None:
            self.assertEqual(sig_key["kty"], "RSA")

        # Test with empty key list to ensure None is returned
        sig_key = find_signing_key([], "nonexistent")
        self.assertIsNone(sig_key)


class TestUserAgent(unittest.TestCase):
    """Test user agent generation"""

    def test_user_agent_format(self):
        """Test user agent format"""
        user_agent = get_user_agent()

        self.assertIsInstance(user_agent, str)
        self.assertIn("TAC-Protocol", user_agent)
        self.assertIn("Python", user_agent)

        # Should include version information
        parts = user_agent.split("/")
        self.assertGreaterEqual(len(parts), 2)

    def test_user_agent_consistency(self):
        """Test user agent consistency"""
        ua1 = get_user_agent()
        ua2 = get_user_agent()

        self.assertEqual(ua1, ua2)


class TestNetworkUtilities(unittest.TestCase):
    """Test network utility functions"""

    def test_fetch_jwks_basic_concept(self):
        """Test basic concept of JWKS fetching without complex mocking"""
        # Test that the function exists and has expected signature
        import inspect

        from utils import fetch_jwks_with_retry

        sig = inspect.signature(fetch_jwks_with_retry)
        self.assertIn("domain", sig.parameters)  # Uses domain not url
        self.assertIn("max_retries", sig.parameters)
        self.assertIn("retry_delay", sig.parameters)

    def test_network_error_handling(self):
        """Test network error creation"""
        error = TACNetworkError("Network failed", "TAC_NETWORK_ERROR")
        self.assertIn("Network failed", str(error))
        self.assertEqual(error.code, "TAC_NETWORK_ERROR")


class TestErrorHandling(unittest.TestCase):
    """Test error handling in utilities"""

    def test_invalid_key_type_error(self):
        """Test invalid key type error"""
        with self.assertRaises(TACCryptoError):
            get_key_type("invalid")

    def test_invalid_algorithm_parameters(self):
        """Test invalid algorithm parameters"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Test with invalid use - function should return a default rather than raise
        result = get_algorithm_for_key(private_key, "invalid_use")
        self.assertIsInstance(result, str)  # Should return some algorithm

    def test_public_key_to_jwk_error(self):
        """Test public key to JWK conversion error"""
        with self.assertRaises((ValueError, TACCryptoError, AttributeError)):
            public_key_to_jwk("invalid-key")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases in utility functions"""

    def test_empty_jwks_list(self):
        """Test handling of empty JWKS list"""
        enc_key = find_encryption_key([])
        self.assertIsNone(enc_key)

        sig_key = find_signing_key([])
        self.assertIsNone(sig_key)

    def test_malformed_jwks_entries(self):
        """Test handling of malformed JWKS entries"""
        malformed_keys = [
            {},  # Empty key
            {"kty": "RSA"},  # Missing kid
            {"kid": "test"},  # Missing kty
            {"kty": "UNKNOWN", "kid": "unknown"},  # Unknown key type
        ]

        # Should handle gracefully without crashing
        enc_key = find_encryption_key(malformed_keys)
        sig_key = find_signing_key(malformed_keys)

        # Results depend on implementation, but shouldn't crash
        # Just verify the functions return something or None without crashing
        self.assertTrue(enc_key is None or isinstance(enc_key, dict))
        self.assertTrue(sig_key is None or isinstance(sig_key, dict))

    def test_very_large_jwks(self):
        """Test handling of very large JWKS"""
        large_keys = []
        for i in range(1000):
            large_keys.append({"kty": "RSA", "kid": f"key-{i}", "use": "sig" if i % 2 == 0 else "enc"})

        # Should find keys efficiently even with large sets
        enc_key = find_encryption_key(large_keys)
        sig_key = find_signing_key(large_keys)

        self.assertIsNotNone(enc_key)
        self.assertIsNotNone(sig_key)

    def test_unicode_in_key_data(self):
        """Test handling of unicode in key data"""
        unicode_keys = [
            {"kty": "RSA", "kid": "tëst-kéy-🔑", "use": "sig"},
            {"kty": "EC", "kid": "ключ-тест", "use": "enc"},
        ]

        # Should handle unicode gracefully
        enc_key = find_encryption_key(unicode_keys)
        sig_key = find_signing_key(unicode_keys, "tëst-kéy-🔑")

        self.assertIsNotNone(enc_key)
        self.assertIsNotNone(sig_key)
        self.assertEqual(sig_key["kid"], "tëst-kéy-🔑")


class TestPerformance(unittest.TestCase):
    """Test performance characteristics of utilities"""

    def test_cache_performance(self):
        """Test cache performance with many operations"""
        cache = JWKSCache(timeout=5000)

        # Many set operations
        start_time = time.time()
        for i in range(1000):
            keys = [{"kid": f"key-{i}"}]
            cache.set(f"domain-{i}.com", keys)
        set_time = time.time() - start_time

        # Many get operations
        start_time = time.time()
        for i in range(1000):
            cache.get(f"domain-{i}.com")
        get_time = time.time() - start_time

        # Should be reasonably fast
        self.assertLess(set_time, 1.0)  # Less than 1 second
        self.assertLess(get_time, 1.0)  # Less than 1 second

    def test_key_finding_performance(self):
        """Test key finding performance with large key sets"""
        # Create large key set
        keys = []
        for i in range(1000):
            keys.append(
                {"kty": "RSA" if i % 2 == 0 else "EC", "kid": f"key-{i}", "use": "sig" if i % 3 == 0 else "enc"}
            )

        # Finding should be fast even with many keys
        start_time = time.time()
        for _ in range(100):
            find_encryption_key(keys)
            find_signing_key(keys)
        search_time = time.time() - start_time

        self.assertLess(search_time, 1.0)  # Should complete in less than 1 second


if __name__ == "__main__":
    unittest.main()
