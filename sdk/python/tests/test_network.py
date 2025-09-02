#!/usr/bin/env python3
"""
Network Operations Tests for TAC Protocol Python SDK

Simplified tests focusing on core functionality without complex async mocking.
"""

import os
import sys
import unittest

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACErrorCodes, TACNetworkError
from utils import JWKSCache, get_user_agent


class TestJWKSCache(unittest.TestCase):
    """Test JWKS cache functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.cache = JWKSCache(timeout=1000)  # 1 second for testing

    def test_basic_cache_operations(self):
        """Test basic cache set and get operations"""
        keys = [{"kty": "RSA", "use": "sig", "kid": "test-key"}]

        # Test cache miss
        self.assertIsNone(self.cache.get("test.com"))

        # Test cache set and hit
        self.cache.set("test.com", keys)
        cached_keys = self.cache.get("test.com")
        self.assertEqual(cached_keys, keys)

    def test_cache_expiration(self):
        """Test that cache entries expire"""
        import time

        # Use very short timeout
        short_cache = JWKSCache(timeout=100)  # 0.1 seconds
        keys = [{"kty": "RSA", "use": "sig", "kid": "test-key"}]

        short_cache.set("test.com", keys)
        self.assertEqual(short_cache.get("test.com"), keys)

        # Wait for expiration
        time.sleep(0.2)
        self.assertIsNone(short_cache.get("test.com"))

    def test_cache_clear(self):
        """Test cache clearing"""
        keys = [{"kty": "RSA", "use": "sig", "kid": "test-key"}]

        self.cache.set("test1.com", keys)
        self.cache.set("test2.com", keys)

        # Clear specific domain
        self.cache.clear("test1.com")
        self.assertIsNone(self.cache.get("test1.com"))
        self.assertEqual(self.cache.get("test2.com"), keys)

        # Clear all
        self.cache.clear()
        self.assertIsNone(self.cache.get("test2.com"))


class TestNetworkErrorHandling(unittest.TestCase):
    """Test network error handling"""

    def test_network_error_creation(self):
        """Test network error creation"""
        error = TACNetworkError("Test error", TACErrorCodes.HTTP_ERROR)
        self.assertEqual(str(error), "Test error")
        self.assertEqual(error.code, TACErrorCodes.HTTP_ERROR)

    def test_network_error_codes(self):
        """Test network error codes exist"""
        # Verify error codes exist
        self.assertTrue(hasattr(TACErrorCodes, "HTTP_ERROR"))
        self.assertTrue(hasattr(TACErrorCodes, "NETWORK_TIMEOUT"))
        self.assertTrue(hasattr(TACErrorCodes, "JWKS_FETCH_FAILED"))


class TestUserAgent(unittest.TestCase):
    """Test User-Agent functionality"""

    def test_user_agent_format(self):
        """Test User-Agent format"""
        user_agent = get_user_agent()

        # Should contain Python and Protocol information
        self.assertIn("Python", user_agent)
        self.assertIn("TAC-Protocol", user_agent)

    def test_user_agent_consistency(self):
        """Test user agent consistency"""
        ua1 = get_user_agent()
        ua2 = get_user_agent()
        self.assertEqual(ua1, ua2)


class TestNetworkFunctionSignatures(unittest.TestCase):
    """Test network function signatures"""

    def test_fetch_jwks_function_exists(self):
        """Test that fetch function exists and has expected signature"""
        import inspect

        from utils import fetch_jwks_with_retry

        sig = inspect.signature(fetch_jwks_with_retry)

        # Check required parameters exist
        params = sig.parameters
        self.assertIn("domain", params)
        self.assertIn("max_retries", params)
        self.assertIn("retry_delay", params)
        self.assertIn("timeout", params)


if __name__ == "__main__":
    unittest.main()
