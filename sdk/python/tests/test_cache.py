#!/usr/bin/env python3
"""
JWKS Cache Management Tests for TAC Protocol Python SDK

Tests caching behavior, TTL, concurrency, and race conditions.
"""

import os
import sys
import threading
import time
import unittest

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils import JWKSCache


class TestJWKSCache(unittest.TestCase):
    """Test JWKS cache functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.cache = JWKSCache(timeout=1000)  # 1 second timeout

    def test_basic_cache_operations(self):
        """Test basic cache set and get operations"""
        keys = [{"kty": "RSA", "kid": "test-key"}]

        # Test set and get
        self.cache.set("test.com", keys)
        cached_keys = self.cache.get("test.com")

        self.assertEqual(cached_keys, keys)

    def test_cache_miss_returns_none(self):
        """Test that cache miss returns None"""
        result = self.cache.get("nonexistent.com")
        self.assertIsNone(result)

    def test_cache_clear_specific_domain(self):
        """Test clearing cache for specific domain"""
        keys1 = [{"kty": "RSA", "kid": "key1"}]
        keys2 = [{"kty": "RSA", "kid": "key2"}]

        self.cache.set("domain1.com", keys1)
        self.cache.set("domain2.com", keys2)

        # Clear specific domain
        self.cache.clear("domain1.com")

        self.assertIsNone(self.cache.get("domain1.com"))
        self.assertEqual(self.cache.get("domain2.com"), keys2)

    def test_cache_clear_all(self):
        """Test clearing all cache entries"""
        keys1 = [{"kty": "RSA", "kid": "key1"}]
        keys2 = [{"kty": "RSA", "kid": "key2"}]

        self.cache.set("domain1.com", keys1)
        self.cache.set("domain2.com", keys2)

        # Clear all
        self.cache.clear()

        self.assertIsNone(self.cache.get("domain1.com"))
        self.assertIsNone(self.cache.get("domain2.com"))

    def test_cache_ttl_expiration(self):
        """Test that cache entries expire after TTL"""
        # Use very short timeout for testing
        short_cache = JWKSCache(timeout=100)  # 0.1 seconds
        keys = [{"kty": "RSA", "kid": "test-key"}]

        short_cache.set("test.com", keys)

        # Should be available immediately
        self.assertEqual(short_cache.get("test.com"), keys)

        # Wait for expiration
        time.sleep(0.15)  # Wait longer than timeout

        # Should be expired now
        self.assertIsNone(short_cache.get("test.com"))

    def test_cache_ttl_not_expired(self):
        """Test that cache entries are available before TTL expiration"""
        keys = [{"kty": "RSA", "kid": "test-key"}]

        self.cache.set("test.com", keys)

        # Wait less than timeout
        time.sleep(0.1)  # Much less than 1 second timeout

        # Should still be available
        self.assertEqual(self.cache.get("test.com"), keys)

    def test_cache_update_existing_entry(self):
        """Test updating existing cache entry"""
        keys1 = [{"kty": "RSA", "kid": "key1"}]
        keys2 = [{"kty": "RSA", "kid": "key2"}]

        self.cache.set("test.com", keys1)
        self.assertEqual(self.cache.get("test.com"), keys1)

        # Update with new keys
        self.cache.set("test.com", keys2)
        self.assertEqual(self.cache.get("test.com"), keys2)

    def test_cache_different_domains(self):
        """Test cache isolation between different domains"""
        keys1 = [{"kty": "RSA", "kid": "key1"}]
        keys2 = [{"kty": "EC", "kid": "key2"}]

        self.cache.set("domain1.com", keys1)
        self.cache.set("domain2.com", keys2)

        self.assertEqual(self.cache.get("domain1.com"), keys1)
        self.assertEqual(self.cache.get("domain2.com"), keys2)

    def test_cache_empty_keys_list(self):
        """Test caching empty keys list"""
        empty_keys = []

        self.cache.set("test.com", empty_keys)
        self.assertEqual(self.cache.get("test.com"), empty_keys)

    def test_cache_none_keys(self):
        """Test caching None keys (should not cache)"""
        self.cache.set("test.com", None)
        self.assertIsNone(self.cache.get("test.com"))


class TestCacheConcurrency(unittest.TestCase):
    """Test cache behavior under concurrent access"""

    def setUp(self):
        """Set up test fixtures"""
        self.cache = JWKSCache(timeout=5000)  # 5 second timeout

    def test_concurrent_set_operations(self):
        """Test concurrent set operations"""

        def set_keys(domain, key_id):
            keys = [{"kty": "RSA", "kid": key_id}]
            self.cache.set(domain, keys)

        threads = []
        for i in range(10):
            thread = threading.Thread(target=set_keys, args=(f"domain{i}.com", f"key{i}"))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all entries were set
        for i in range(10):
            keys = self.cache.get(f"domain{i}.com")
            self.assertIsNotNone(keys)
            self.assertEqual(keys[0]["kid"], f"key{i}")

    def test_concurrent_get_operations(self):
        """Test concurrent get operations"""
        keys = [{"kty": "RSA", "kid": "test-key"}]
        self.cache.set("test.com", keys)

        results = []

        def get_keys():
            result = self.cache.get("test.com")
            results.append(result)

        threads = []
        for _ in range(10):
            thread = threading.Thread(target=get_keys)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All results should be the same
        self.assertEqual(len(results), 10)
        for result in results:
            self.assertEqual(result, keys)

    def test_concurrent_mixed_operations(self):
        """Test concurrent mixed set/get/clear operations"""
        initial_keys = [{"kty": "RSA", "kid": "initial"}]
        self.cache.set("test.com", initial_keys)

        def mixed_operations(operation_id):
            if operation_id % 3 == 0:
                # Set operation
                keys = [{"kty": "RSA", "kid": f"key{operation_id}"}]
                self.cache.set("test.com", keys)
            elif operation_id % 3 == 1:
                # Get operation
                self.cache.get("test.com")
            else:
                # Clear operation
                self.cache.clear("test.com")

        threads = []
        for i in range(15):
            thread = threading.Thread(target=mixed_operations, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Cache should still be functional (no crashes)
        test_keys = [{"kty": "RSA", "kid": "final-test"}]
        self.cache.set("final.com", test_keys)
        self.assertEqual(self.cache.get("final.com"), test_keys)


class TestCachePerformance(unittest.TestCase):
    """Test cache performance characteristics"""

    def setUp(self):
        """Set up test fixtures"""
        self.cache = JWKSCache(timeout=10000)  # 10 second timeout

    def test_large_number_of_domains(self):
        """Test cache with large number of domains"""
        num_domains = 1000

        # Set keys for many domains
        start_time = time.time()
        for i in range(num_domains):
            keys = [{"kty": "RSA", "kid": f"key{i}"}]
            self.cache.set(f"domain{i}.com", keys)
        set_duration = time.time() - start_time

        # Get keys for many domains
        start_time = time.time()
        for i in range(num_domains):
            keys = self.cache.get(f"domain{i}.com")
            self.assertIsNotNone(keys)
        get_duration = time.time() - start_time

        # Performance should be reasonable
        self.assertLess(set_duration, 1.0)  # Should complete in less than 1 second
        self.assertLess(get_duration, 1.0)  # Should complete in less than 1 second

    def test_large_keys_payload(self):
        """Test cache with large keys payload"""
        # Create large keys list
        large_keys = []
        for i in range(100):
            key = {
                "kty": "RSA",
                "kid": f"key{i}",
                "n": "x" * 1000,  # Large modulus
                "e": "AQAB",
                "metadata": {"description": f"Large key {i}" * 10},
            }
            large_keys.append(key)

        # Should handle large payloads
        start_time = time.time()
        self.cache.set("large.com", large_keys)
        set_duration = time.time() - start_time

        start_time = time.time()
        cached_keys = self.cache.get("large.com")
        get_duration = time.time() - start_time

        self.assertEqual(cached_keys, large_keys)
        self.assertLess(set_duration, 0.1)  # Should be fast
        self.assertLess(get_duration, 0.1)  # Should be fast


class TestCacheEdgeCases(unittest.TestCase):
    """Test cache edge cases and error conditions"""

    def setUp(self):
        """Set up test fixtures"""
        self.cache = JWKSCache(timeout=1000)

    def test_zero_timeout(self):
        """Test cache with zero timeout"""
        zero_cache = JWKSCache(timeout=0)
        keys = [{"kty": "RSA", "kid": "test"}]

        zero_cache.set("test.com", keys)

        # Should expire immediately
        self.assertIsNone(zero_cache.get("test.com"))

    def test_negative_timeout(self):
        """Test cache with negative timeout"""
        # Should handle gracefully or use default
        try:
            negative_cache = JWKSCache(timeout=-1000)
            keys = [{"kty": "RSA", "kid": "test"}]
            negative_cache.set("test.com", keys)
            # If it doesn't raise an error, should not cache or expire immediately
            result = negative_cache.get("test.com")
            self.assertIsNone(result)
        except ValueError:
            # It's also acceptable to raise ValueError for negative timeout
            pass

    def test_very_large_timeout(self):
        """Test cache with very large timeout"""
        large_cache = JWKSCache(timeout=999999999)  # Very large timeout
        keys = [{"kty": "RSA", "kid": "test"}]

        large_cache.set("test.com", keys)
        self.assertEqual(large_cache.get("test.com"), keys)

    def test_cache_with_special_domain_names(self):
        """Test cache with special domain names"""
        keys = [{"kty": "RSA", "kid": "test"}]

        special_domains = [
            "localhost",
            "127.0.0.1",
            "test-domain.co.uk",
            "sub.domain.example.com",
            "domain_with_underscores.org",
            "xn--fsq.example.com",  # IDN domain
        ]

        for domain in special_domains:
            self.cache.set(domain, keys)
            self.assertEqual(self.cache.get(domain), keys)

    def test_cache_stress_expiration(self):
        """Test cache under stress with many expirations"""
        short_cache = JWKSCache(timeout=50)  # Very short timeout

        # Add many entries quickly
        for i in range(100):
            keys = [{"kty": "RSA", "kid": f"key{i}"}]
            short_cache.set(f"domain{i}.com", keys)

        # Wait for some to expire
        time.sleep(0.1)

        # Add more entries
        for i in range(100, 200):
            keys = [{"kty": "RSA", "kid": f"key{i}"}]
            short_cache.set(f"domain{i}.com", keys)

        # Cache should still be functional
        test_keys = [{"kty": "RSA", "kid": "final"}]
        short_cache.set("final.com", test_keys)
        self.assertEqual(short_cache.get("final.com"), test_keys)


if __name__ == "__main__":
    unittest.main()
