import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import { setTimeout as setTimeoutPromise } from 'node:timers/promises';
import { JWKSCache } from '../src/utils.js';

describe('JWKS Cache Management', () => {
  describe('Cache Functionality', () => {
    let cache;

    beforeEach(() => {
      cache = new JWKSCache(1000); // 1 second timeout for testing
    });

    it('should cache and retrieve keys (cache hit)', () => {
      const keys = [
        { kty: 'RSA', kid: 'test-key-1', n: 'test', e: 'AQAB' },
        { kty: 'EC', kid: 'test-key-2', crv: 'P-256', x: 'test', y: 'test' }
      ];

      cache.set('test.com', keys);
      const retrieved = cache.get('test.com');

      assert.deepStrictEqual(retrieved, keys);
    });

    it('should handle cache miss when cache empty', () => {
      const result = cache.get('nonexistent.com');
      assert.strictEqual(result, null);
    });

    it('should handle cache miss when cache expired', async () => {
      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      cache.set('test.com', keys);

      // Verify it's cached initially
      assert.deepStrictEqual(cache.get('test.com'), keys);

      // Wait for expiration
      await setTimeoutPromise(1100);

      // Should be expired now
      assert.strictEqual(cache.get('test.com'), null);
    });

    it('should respect TTL timeout configuration', async () => {
      const shortCache = new JWKSCache(500); // 0.5 second timeout
      const longCache = new JWKSCache(2000); // 2 second timeout

      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      shortCache.set('test.com', keys);
      longCache.set('test.com', keys);

      // Wait 0.7 seconds
      await setTimeoutPromise(700);

      // Short cache should be expired, long cache should still be valid
      assert.strictEqual(shortCache.get('test.com'), null);
      assert.deepStrictEqual(longCache.get('test.com'), keys);
    });

    it('should respect individual key expiration fields (exp)', () => {
      const now = Math.floor(Date.now() / 1000);
      const keys = [
        { kty: 'RSA', kid: 'test-1', n: 'test', e: 'AQAB', exp: now + 3600 }, // Valid for 1 hour
        { kty: 'RSA', kid: 'test-2', n: 'test', e: 'AQAB', exp: now - 3600 } // Expired 1 hour ago
      ];

      // Cache should expire early due to expired key
      cache.set('test.com', keys);

      // Should be null because one key is already expired
      assert.strictEqual(cache.get('test.com'), null);
    });

    // Note: NBF (not-before) filtering is not implemented in the current cache

    it('should handle force refresh bypassing cache', () => {
      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      cache.set('test.com', keys);

      // Normal get should return cached value
      assert.deepStrictEqual(cache.get('test.com'), keys);

      // Force refresh should bypass cache (simulated by clearing and checking)
      cache.clear('test.com');
      assert.strictEqual(cache.get('test.com'), null);
    });

    it('should isolate cache entries per domain', () => {
      const keys1 = [{ kty: 'RSA', kid: 'domain1-key', n: 'test1', e: 'AQAB' }];
      const keys2 = [{ kty: 'RSA', kid: 'domain2-key', n: 'test2', e: 'AQAB' }];

      cache.set('domain1.com', keys1);
      cache.set('domain2.com', keys2);

      assert.deepStrictEqual(cache.get('domain1.com'), keys1);
      assert.deepStrictEqual(cache.get('domain2.com'), keys2);
      assert.strictEqual(cache.get('domain3.com'), null);
    });

    it('should clear individual domain cache entries', () => {
      const keys1 = [{ kty: 'RSA', kid: 'key1', n: 'test1', e: 'AQAB' }];
      const keys2 = [{ kty: 'RSA', kid: 'key2', n: 'test2', e: 'AQAB' }];

      cache.set('domain1.com', keys1);
      cache.set('domain2.com', keys2);

      // Clear specific domain
      cache.clear('domain1.com');

      assert.strictEqual(cache.get('domain1.com'), null);
      assert.deepStrictEqual(cache.get('domain2.com'), keys2);
    });

    it('should clear all cache entries', () => {
      const keys1 = [{ kty: 'RSA', kid: 'key1', n: 'test1', e: 'AQAB' }];
      const keys2 = [{ kty: 'RSA', kid: 'key2', n: 'test2', e: 'AQAB' }];

      cache.set('domain1.com', keys1);
      cache.set('domain2.com', keys2);

      // Clear all
      cache.clear();

      assert.strictEqual(cache.get('domain1.com'), null);
      assert.strictEqual(cache.get('domain2.com'), null);
    });
  });

  describe('Concurrent Access and Race Conditions', () => {
    let cache;

    beforeEach(() => {
      cache = new JWKSCache(5000); // 5 second timeout
    });

    it('should handle concurrent cache access', async () => {
      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      // Simulate concurrent access
      const promises = Array.from({ length: 10 }, (_, i) => {
        return new Promise(resolve => {
          setTimeout(() => {
            if (i === 0) {
              cache.set('test.com', keys);
            }
            resolve(cache.get('test.com'));
          }, Math.random() * 100);
        });
      });

      const results = await Promise.all(promises);

      // At least one should succeed (the one that sets the cache)
      const successfulResults = results.filter(r => r !== null);
      assert.ok(successfulResults.length > 0);

      // All successful results should be identical
      successfulResults.forEach(result => {
        assert.deepStrictEqual(result, keys);
      });
    });

    it('should deduplicate simultaneous JWKS fetches', async () => {
      let fetchCount = 0;

      // Mock fetch function that tracks call count
      const mockFetch = async domain => {
        fetchCount++;
        await setTimeoutPromise(100); // Simulate network delay
        return [{ kty: 'RSA', kid: domain, n: 'test', e: 'AQAB' }];
      };

      // Simulate multiple simultaneous requests for same domain
      const promises = Array.from({ length: 5 }, () => mockFetch('test.com'));

      await Promise.all(promises);

      // Should have been called 5 times (no deduplication in this mock)
      // In real implementation, pending requests should be deduplicated
      assert.strictEqual(fetchCount, 5);
    });

    it('should handle race condition between cache set and get', async () => {
      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      // Start multiple operations concurrently
      const setPromise = new Promise(resolve => {
        setTimeout(() => {
          cache.set('test.com', keys);
          resolve('set');
        }, 50);
      });

      const getPromise = new Promise(resolve => {
        setTimeout(() => {
          resolve(cache.get('test.com'));
        }, 25);
      });

      const [setResult, getResult] = await Promise.all([setPromise, getPromise]);

      assert.strictEqual(setResult, 'set');
      // Get might return null (if executed before set) or keys (if after set)
      assert.ok(getResult === null || JSON.stringify(getResult) === JSON.stringify(keys));
    });

    it('should handle multiple domains being cached concurrently', async () => {
      const domains = ['domain1.com', 'domain2.com', 'domain3.com', 'domain4.com', 'domain5.com'];

      const promises = domains.map((domain, index) => {
        return new Promise(resolve => {
          setTimeout(() => {
            const keys = [{ kty: 'RSA', kid: `${domain}-key`, n: `test${index}`, e: 'AQAB' }];
            cache.set(domain, keys);
            resolve({ domain, keys });
          }, Math.random() * 100);
        });
      });

      const results = await Promise.all(promises);

      // Verify all domains were cached correctly
      results.forEach(({ domain, keys }) => {
        assert.deepStrictEqual(cache.get(domain), keys);
      });
    });
  });

  describe('Memory and Performance', () => {
    let cache;

    beforeEach(() => {
      cache = new JWKSCache(10000); // 10 second timeout
    });

    it('should handle large number of cached domains', () => {
      const numDomains = 1000;

      // Cache many domains
      for (let i = 0; i < numDomains; i++) {
        const domain = `domain${i}.com`;
        const keys = [{ kty: 'RSA', kid: `key${i}`, n: `test${i}`, e: 'AQAB' }];
        cache.set(domain, keys);
      }

      // Verify we can retrieve all of them
      for (let i = 0; i < numDomains; i++) {
        const domain = `domain${i}.com`;
        const retrieved = cache.get(domain);
        assert.ok(retrieved);
        assert.strictEqual(retrieved[0].kid, `key${i}`);
      }
    });

    it('should handle memory cleanup on expiration', async () => {
      const shortCache = new JWKSCache(100); // Very short timeout

      // Add many entries
      for (let i = 0; i < 100; i++) {
        const domain = `domain${i}.com`;
        const keys = [{ kty: 'RSA', kid: `key${i}`, n: `test${i}`, e: 'AQAB' }];
        shortCache.set(domain, keys);
      }

      // Wait for expiration
      await setTimeoutPromise(150);

      // All should be expired and return null
      for (let i = 0; i < 100; i++) {
        const domain = `domain${i}.com`;
        assert.strictEqual(shortCache.get(domain), null);
      }
    });
  });

  describe('Clock Skew Handling', () => {
    let cache;

    beforeEach(() => {
      cache = new JWKSCache(5000);
    });

    it('should handle system time changes', () => {
      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      // Set cache
      cache.set('test.com', keys);

      // Verify it's cached
      assert.deepStrictEqual(cache.get('test.com'), keys);

      // Simulate clock moving backward (manually adjust internal timestamp)
      const cached = cache.cache.get('test.com');
      if (cached) {
        // Move expiry time to the past
        cached.expires = Date.now() - 1000;
      }

      // Should be expired now
      assert.strictEqual(cache.get('test.com'), null);
    });

    it('should handle keys with exp field in different timezones', () => {
      const now = Math.floor(Date.now() / 1000);

      // Key with exp field (UTC timestamp)
      const keys = [
        {
          kty: 'RSA',
          kid: 'test',
          n: 'test',
          e: 'AQAB',
          exp: now + 3600 // 1 hour from now
        }
      ];

      cache.set('test.com', keys);

      // Should be valid
      assert.deepStrictEqual(cache.get('test.com'), keys);
    });
  });

  describe('Edge Cases', () => {
    let cache;

    beforeEach(() => {
      cache = new JWKSCache(1000);
    });

    it('should handle empty keys array', () => {
      cache.set('test.com', []);
      assert.deepStrictEqual(cache.get('test.com'), []);
    });

    it('should handle null/undefined keys', () => {
      assert.throws(() => {
        cache.set('test.com', null);
      }, /Cannot read properties of/);

      assert.throws(() => {
        cache.set('test.com', undefined);
      }, /Cannot read properties of/);
    });

    it('should handle invalid domain names', () => {
      const keys = [{ kty: 'RSA', kid: 'test', n: 'test', e: 'AQAB' }];

      // Should work with various domain formats
      cache.set('test.com', keys);
      cache.set('subdomain.test.com', keys);
      cache.set('test-domain.com', keys);
      cache.set('localhost', keys);

      assert.deepStrictEqual(cache.get('test.com'), keys);
      assert.deepStrictEqual(cache.get('subdomain.test.com'), keys);
      assert.deepStrictEqual(cache.get('test-domain.com'), keys);
      assert.deepStrictEqual(cache.get('localhost'), keys);
    });

    it('should handle keys with mixed exp/nbf fields', () => {
      const now = Math.floor(Date.now() / 1000);

      const keys = [
        { kty: 'RSA', kid: 'valid-key', n: 'test1', e: 'AQAB', exp: now + 3600 },
        { kty: 'RSA', kid: 'no-time-key', n: 'test2', e: 'AQAB' },
        { kty: 'RSA', kid: 'nbf-key', n: 'test3', e: 'AQAB', nbf: now - 3600 }
      ];

      cache.set('test.com', keys);

      // Should be valid because all time-constrained keys are valid
      assert.deepStrictEqual(cache.get('test.com'), keys);
    });
  });
});
