import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";
import { setTimeout as setTimeoutPromise } from "node:timers/promises";
import { JWKSCache } from "../src/utils.js";

describe("JWKS Cache Management", () => {
  describe("Cache Functionality", () => {
    let cache: JWKSCache;

    beforeEach(() => {
      cache = new JWKSCache(1000); // 1 second timeout for testing
    });

    it("should cache and retrieve keys (cache hit)", () => {
      const keys = [
        { kty: "RSA", kid: "test-key-1", n: "test", e: "AQAB" },
        { kty: "EC", kid: "test-key-2", crv: "P-256", x: "test", y: "test" },
      ];

      cache.set("test.com", keys);
      const retrieved = cache.get("test.com");

      assert.deepStrictEqual(retrieved, keys);
    });

    it("should handle cache miss when cache empty", () => {
      const result = cache.get("nonexistent.com");
      assert.strictEqual(result, null);
    });

    it("should handle cache miss when cache expired", async () => {
      const keys = [{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }];

      cache.set("test.com", keys);

      // Verify it's cached initially
      assert.deepStrictEqual(cache.get("test.com"), keys);

      // Wait for expiration
      await setTimeoutPromise(1100);

      // Should be expired now
      assert.strictEqual(cache.get("test.com"), null);
    });

    it("should respect TTL timeout configuration", async () => {
      const shortCache = new JWKSCache(500); // 0.5 second timeout
      const longCache = new JWKSCache(2000); // 2 second timeout

      const keys = [{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }];

      shortCache.set("test.com", keys);
      longCache.set("test.com", keys);

      // Wait 0.7 seconds
      await setTimeoutPromise(700);

      // Short cache should be expired, long cache should still be valid
      assert.strictEqual(shortCache.get("test.com"), null);
      assert.deepStrictEqual(longCache.get("test.com"), keys);
    });

    it("should respect individual key expiration fields (exp)", () => {
      const now = Math.floor(Date.now() / 1000);
      const keys = [
        { kty: "RSA", kid: "test-1", n: "test", e: "AQAB", exp: now + 3600 }, // Valid for 1 hour
        { kty: "RSA", kid: "test-2", n: "test", e: "AQAB", exp: now - 3600 }, // Expired 1 hour ago
      ];

      // Cache should expire early due to expired key
      cache.set("test.com", keys);

      // Should be null because one key is already expired
      assert.strictEqual(cache.get("test.com"), null);
    });

    it("should handle force refresh bypassing cache", () => {
      const keys = [{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }];

      cache.set("test.com", keys);

      // Normal get should return cached value
      assert.deepStrictEqual(cache.get("test.com"), keys);

      // Force refresh should bypass cache (simulated by clearing and checking)
      cache.clear("test.com");
      assert.strictEqual(cache.get("test.com"), null);
    });

    it("should isolate cache entries per domain", () => {
      const keys1 = [{ kty: "RSA", kid: "domain1-key", n: "test1", e: "AQAB" }];
      const keys2 = [{ kty: "RSA", kid: "domain2-key", n: "test2", e: "AQAB" }];

      cache.set("domain1.com", keys1);
      cache.set("domain2.com", keys2);

      assert.deepStrictEqual(cache.get("domain1.com"), keys1);
      assert.deepStrictEqual(cache.get("domain2.com"), keys2);

      // Clearing one shouldn't affect the other
      cache.clear("domain1.com");
      assert.strictEqual(cache.get("domain1.com"), null);
      assert.deepStrictEqual(cache.get("domain2.com"), keys2);
    });

    it("should clear all cache entries", () => {
      const keys1 = [{ kty: "RSA", kid: "test1", n: "test1", e: "AQAB" }];
      const keys2 = [{ kty: "RSA", kid: "test2", n: "test2", e: "AQAB" }];

      cache.set("domain1.com", keys1);
      cache.set("domain2.com", keys2);

      // Both should be cached
      assert.deepStrictEqual(cache.get("domain1.com"), keys1);
      assert.deepStrictEqual(cache.get("domain2.com"), keys2);

      // Clear all
      cache.clear();

      // Both should be gone
      assert.strictEqual(cache.get("domain1.com"), null);
      assert.strictEqual(cache.get("domain2.com"), null);
    });
  });

  describe("Pending Request Deduplication", () => {
    let cache: JWKSCache;

    beforeEach(() => {
      cache = new JWKSCache(5000);
    });

    it("should store and retrieve pending fetch promises", () => {
      const mockPromise = Promise.resolve([{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }]);

      cache.setPendingFetch("test.com", mockPromise);
      const retrieved = cache.getPendingFetch("test.com");

      assert.strictEqual(retrieved, mockPromise);
    });

    it("should return undefined for non-existent pending fetches", () => {
      const result = cache.getPendingFetch("nonexistent.com");
      assert.strictEqual(result, undefined);
    });

    it("should delete pending fetches", () => {
      const mockPromise = Promise.resolve([{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }]);

      cache.setPendingFetch("test.com", mockPromise);
      assert.strictEqual(cache.getPendingFetch("test.com"), mockPromise);

      cache.deletePendingFetch("test.com");
      assert.strictEqual(cache.getPendingFetch("test.com"), undefined);
    });

    it("should isolate pending fetches per domain", () => {
      const promise1 = Promise.resolve([{ kty: "RSA", kid: "test1", n: "test1", e: "AQAB" }]);
      const promise2 = Promise.resolve([{ kty: "RSA", kid: "test2", n: "test2", e: "AQAB" }]);

      cache.setPendingFetch("domain1.com", promise1);
      cache.setPendingFetch("domain2.com", promise2);

      assert.strictEqual(cache.getPendingFetch("domain1.com"), promise1);
      assert.strictEqual(cache.getPendingFetch("domain2.com"), promise2);

      // Deleting one shouldn't affect the other
      cache.deletePendingFetch("domain1.com");
      assert.strictEqual(cache.getPendingFetch("domain1.com"), undefined);
      assert.strictEqual(cache.getPendingFetch("domain2.com"), promise2);
    });

    it("should clear pending fetches when clearing specific domain", () => {
      const keys = [{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }];
      const mockPromise = Promise.resolve(keys);

      cache.set("test.com", keys);
      cache.setPendingFetch("test.com", mockPromise);

      // Both cache and pending fetch should exist
      assert.deepStrictEqual(cache.get("test.com"), keys);
      assert.strictEqual(cache.getPendingFetch("test.com"), mockPromise);

      // Clear specific domain
      cache.clear("test.com");

      // Both should be gone
      assert.strictEqual(cache.get("test.com"), null);
      assert.strictEqual(cache.getPendingFetch("test.com"), undefined);
    });

    it("should clear all pending fetches when clearing all", () => {
      const promise1 = Promise.resolve([{ kty: "RSA", kid: "test1", n: "test1", e: "AQAB" }]);
      const promise2 = Promise.resolve([{ kty: "RSA", kid: "test2", n: "test2", e: "AQAB" }]);

      cache.setPendingFetch("domain1.com", promise1);
      cache.setPendingFetch("domain2.com", promise2);

      // Both should exist
      assert.strictEqual(cache.getPendingFetch("domain1.com"), promise1);
      assert.strictEqual(cache.getPendingFetch("domain2.com"), promise2);

      // Clear all
      cache.clear();

      // Both should be gone
      assert.strictEqual(cache.getPendingFetch("domain1.com"), undefined);
      assert.strictEqual(cache.getPendingFetch("domain2.com"), undefined);
    });
  });

  describe("Edge Cases and Error Handling", () => {
    let cache: JWKSCache;

    beforeEach(() => {
      cache = new JWKSCache(1000);
    });

    it("should handle empty key arrays", () => {
      const keys: any[] = [];

      cache.set("test.com", keys);
      const retrieved = cache.get("test.com");

      assert.deepStrictEqual(retrieved, keys);
    });

    it("should handle null/undefined domain gracefully", () => {
      // These operations should not throw errors
      assert.doesNotThrow(() => {
        cache.get("" as any);
        cache.set("" as any, []);
        cache.clear("" as any);
        cache.getPendingFetch("" as any);
        cache.setPendingFetch("" as any, Promise.resolve([]));
        cache.deletePendingFetch("" as any);
      });
    });

    it("should handle keys with mixed expiration scenarios", () => {
      const now = Math.floor(Date.now() / 1000);
      const keys = [
        { kty: "RSA", kid: "no-exp", n: "test", e: "AQAB" }, // No expiration
        { kty: "RSA", kid: "future-exp", n: "test", e: "AQAB", exp: now + 3600 }, // Future expiration
        { kty: "RSA", kid: "far-future", n: "test", e: "AQAB", exp: now + 7200 }, // Far future expiration
      ];

      cache.set("test.com", keys);

      // Should use the earliest expiration (1 hour from now)
      const retrieved = cache.get("test.com");
      assert.deepStrictEqual(retrieved, keys);
    });

    it("should handle very short timeout values", async () => {
      const ultraShortCache = new JWKSCache(10); // 10ms timeout
      const keys = [{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }];

      ultraShortCache.set("test.com", keys);

      // Should be cached initially
      assert.deepStrictEqual(ultraShortCache.get("test.com"), keys);

      // Wait 20ms
      await setTimeoutPromise(20);

      // Should be expired
      assert.strictEqual(ultraShortCache.get("test.com"), null);
    });

    it("should handle very long timeout values", () => {
      const longCache = new JWKSCache(86400000); // 24 hours
      const keys = [{ kty: "RSA", kid: "test", n: "test", e: "AQAB" }];

      longCache.set("test.com", keys);
      const retrieved = longCache.get("test.com");

      assert.deepStrictEqual(retrieved, keys);
    });

    it("should handle multiple rapid set/get operations", () => {
      const keys1 = [{ kty: "RSA", kid: "test1", n: "test1", e: "AQAB" }];
      const keys2 = [{ kty: "RSA", kid: "test2", n: "test2", e: "AQAB" }];
      const keys3 = [{ kty: "RSA", kid: "test3", n: "test3", e: "AQAB" }];

      // Rapid operations
      cache.set("test.com", keys1);
      cache.set("test.com", keys2);
      cache.set("test.com", keys3);

      const retrieved = cache.get("test.com");
      assert.deepStrictEqual(retrieved, keys3); // Should have the last set value
    });

    it("should handle concurrent pending fetch operations", () => {
      const promise1 = Promise.resolve([{ kty: "RSA", kid: "test1", n: "test1", e: "AQAB" }]);
      const promise2 = Promise.resolve([{ kty: "RSA", kid: "test2", n: "test2", e: "AQAB" }]);

      // Set multiple pending fetches for same domain (simulating race condition)
      cache.setPendingFetch("test.com", promise1);
      cache.setPendingFetch("test.com", promise2);

      // Should have the last set promise
      assert.strictEqual(cache.getPendingFetch("test.com"), promise2);
    });
  });
});
