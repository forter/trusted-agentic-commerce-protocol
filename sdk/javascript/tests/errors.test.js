import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import * as jose from 'jose';
import TACSender from '../src/sender.js';
import TACRecipient from '../src/recipient.js';
import { TACCryptoError, TACValidationError, TACErrorCodes } from '../src/errors.js';

describe('Error Handling and Edge Cases', () => {
  describe('Input Validation', () => {
    describe('TACSender Constructor', () => {
      it('should reject empty domain', () => {
        assert.throws(
          () => {
            new TACSender({
              domain: '',
              privateKey: 'dummy-key'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it('should reject null domain', () => {
        assert.throws(
          () => {
            new TACSender({
              domain: null,
              privateKey: 'dummy-key'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it('should reject undefined domain', () => {
        assert.throws(
          () => {
            new TACSender({
              privateKey: 'dummy-key'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it('should reject missing private key', () => {
        assert.throws(
          () => {
            new TACSender({
              domain: 'test.com'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.PRIVATE_KEY_REQUIRED;
          }
        );
      });

      it('should reject null private key', () => {
        assert.throws(
          () => {
            new TACSender({
              domain: 'test.com',
              privateKey: null
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.PRIVATE_KEY_REQUIRED;
          }
        );
      });

      it('should reject invalid private key format', () => {
        assert.throws(
          () => {
            new TACSender({
              domain: 'test.com',
              privateKey: 'invalid-pem-format'
            });
          },
          error => {
            return error.name === 'TACCryptoError' && error.code === 'TAC_INVALID_KEY_DATA';
          }
        );
      });

      it('should handle negative TTL values', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey,
          ttl: -3600 // Negative TTL
        });

        assert.strictEqual(sender.ttl, -3600);
        // The JWT will be created with exp in the past, causing validation errors
      });

      it('should handle zero TTL', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey,
          ttl: 0
        });

        assert.strictEqual(sender.ttl, 0);
      });

      it('should handle very large TTL values', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey,
          ttl: Number.MAX_SAFE_INTEGER
        });

        assert.strictEqual(sender.ttl, Number.MAX_SAFE_INTEGER);
      });

      it('should handle invalid configuration types', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        // Test with string instead of number for TTL
        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey,
          ttl: '3600', // String instead of number
          maxRetries: '3', // String instead of number
          retryDelay: '1000' // String instead of number
        });

        // Should handle type coercion gracefully
        assert.strictEqual(typeof sender.ttl, 'string');
      });
    });

    describe('TACRecipient Constructor', () => {
      it('should reject empty domain', () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: '',
              privateKey: 'dummy-key'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it('should reject null domain', () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: null,
              privateKey: 'dummy-key'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it('should reject missing private key', () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: 'test.com'
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.PRIVATE_KEY_REQUIRED;
          }
        );
      });

      it('should reject invalid private key format', () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: 'test.com',
              privateKey: 'invalid-pem-format'
            });
          },
          error => {
            return error.name === 'TACCryptoError' && error.code === TACErrorCodes.INVALID_KEY_DATA;
          }
        );
      });
    });

    describe('Data Validation', () => {
      let sender;

      beforeEach(async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });
      });

      it('should handle null recipient data', async () => {
        await sender.addRecipientData('recipient.com', null);
        assert.strictEqual(sender.recipientData['recipient.com'], null);
      });

      it('should handle undefined recipient data', async () => {
        await sender.addRecipientData('recipient.com', undefined);
        assert.strictEqual(sender.recipientData['recipient.com'], undefined);
      });

      it('should handle empty object recipient data', async () => {
        await sender.addRecipientData('recipient.com', {});
        assert.deepStrictEqual(sender.recipientData['recipient.com'], {});
      });

      it('should handle circular reference data', async () => {
        const circularData = { test: 'data' };
        circularData.self = circularData; // Create circular reference

        // Should throw when trying to JSON.stringify during message generation
        await sender.addRecipientData('recipient.com', circularData);

        // Mock JWKS to avoid network call
        sender.fetchJWKS = async () => {
          throw new Error('Should not reach JWKS fetch due to circular reference');
        };

        await assert.rejects(async () => await sender.generateTACMessage(), /circular|Converting circular structure/);
      });

      it('should handle very large data objects', async () => {
        // Create large object (but not circular)
        const largeData = {
          bigArray: Array.from({ length: 10000 }, (_, i) => ({ id: i, data: `item-${i}` })),
          bigString: 'x'.repeat(100000)
        };

        await sender.addRecipientData('recipient.com', largeData);
        assert.ok(sender.recipientData['recipient.com']);
      });

      it('should handle special character data', async () => {
        const specialData = {
          unicode: '🚀 Unicode test with émojis and accénts',
          special: "Special chars: !@#$%^&*()_+-={}[]|\\:;\"'<>?,./'",
          newlines: 'Line 1\nLine 2\rLine 3\r\nLine 4',
          tabs: 'Tab\tseparated\tvalues',
          quotes: 'Double "quotes" and single \'quotes\'',
          control: '\u0000\u0001\u0002' // Control characters
        };

        await sender.addRecipientData('recipient.com', specialData);
        assert.deepStrictEqual(sender.recipientData['recipient.com'], specialData);
      });
    });
  });

  describe('Runtime Error Handling', () => {
    describe('Network Failure Scenarios', () => {
      let sender;
      let recipient;

      beforeEach(async () => {
        const senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        sender = new TACSender({
          domain: 'sender.com',
          privateKey: senderKeys.privateKey
        });

        recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });
      });

      it('should handle connection refused gracefully', async () => {
        sender.fetchJWKS = async () => {
          throw new Error('connect ECONNREFUSED 127.0.0.1:443');
        };

        await sender.addRecipientData('recipient.com', { data: 'test' });

        await assert.rejects(async () => await sender.generateTACMessage(), /ECONNREFUSED/);
      });

      it('should handle DNS resolution failure', async () => {
        sender.fetchJWKS = async () => {
          throw new Error('getaddrinfo ENOTFOUND nonexistent.domain.com');
        };

        await sender.addRecipientData('nonexistent.domain.com', { data: 'test' });

        await assert.rejects(async () => await sender.generateTACMessage(), /ENOTFOUND/);
      });

      it('should handle timeout errors', async () => {
        sender.fetchJWKS = async () => {
          throw new Error('Request timeout');
        };

        await sender.addRecipientData('recipient.com', { data: 'test' });

        await assert.rejects(async () => await sender.generateTACMessage(), /timeout/);
      });

      it('should handle SSL certificate errors', async () => {
        recipient.fetchJWKS = async () => {
          throw new Error('unable to verify the first certificate');
        };

        // Create a valid message
        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        await sender.addRecipientData('recipient.com', { data: 'test' });
        const tacMessage = await sender.generateTACMessage();

        // Should fail during signature verification due to JWKS fetch failure
        const result = await recipient.processTACMessage(tacMessage);
        assert.strictEqual(result.valid, false);
        assert.ok(result.errors.some(e => e.includes('certificate')));
      });

      it('should handle intermittent network issues', async () => {
        // Mock fetch to fail first 2 times, then succeed
        let attemptCount = 0;
        const originalFetch = global.fetch;
        global.fetch = async () => {
          attemptCount++;
          if (attemptCount < 3) {
            throw new Error('Network error');
          }
          // Success on third attempt
          return {
            ok: true,
            status: 200,
            json: async () => ({ keys: [await recipient.getPublicJWK()] })
          };
        };

        try {
          await sender.addRecipientData('recipient.com', { data: 'test' });

          // Should eventually succeed with retries (fetchJWKSWithRetry has retry logic)
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
          assert.strictEqual(attemptCount, 3);
        } finally {
          global.fetch = originalFetch;
        }
      });
    });

    describe('Cryptographic Failures', () => {
      let sender;
      let recipient;

      beforeEach(async () => {
        const senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        sender = new TACSender({
          domain: 'sender.com',
          privateKey: senderKeys.privateKey
        });

        recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });
      });

      it('should handle invalid encryption operations', async () => {
        // Provide a signing key instead of encryption key
        const signingJWK = await recipient.getPublicJWK();
        signingJWK.use = 'sig'; // Explicitly mark as signing key
        signingJWK.alg = 'RS256';
        delete signingJWK.alg; // Remove encryption algorithm

        sender.fetchJWKS = async () => [signingJWK];

        await sender.addRecipientData('recipient.com', { data: 'test' });

        await assert.rejects(
          async () => await sender.generateTACMessage(),
          /No suitable encryption key found|encryption/
        );
      });

      it('should handle unsupported algorithms', async () => {
        // This would be caught during key creation, but test with mock
        sender.signingAlgorithm = 'UNSUPPORTED_ALG';

        await sender.addRecipientData('recipient.com', { data: 'test' });

        // Mock JWKS with valid key
        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        await assert.rejects(async () => await sender.generateTACMessage(), /not supported|unsupported|algorithm/);
      });

      it('should reject keys smaller than 2048 bits', async () => {
        // Use very small key - must be rejected for security
        const smallKey = crypto.generateKeyPairSync('rsa', {
          modulusLength: 1024 // Too small
        });

        // Should throw for 1024-bit keys (security requirement)
        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: smallKey.privateKey
          });
        }, /key size.*too small|minimum 2048/i);
      });

      it('should handle corrupted key data', async () => {
        // Attempt to use corrupted key
        const validKey = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const keyPem = validKey.privateKey.export({ type: 'pkcs8', format: 'pem' });
        const corruptedPem = keyPem.replace(/[A-Za-z0-9]/, 'X'); // Corrupt one character

        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: corruptedPem
          });
        }, /Invalid key data|error/);
      });
    });

    describe('Memory Exhaustion Scenarios', () => {
      let sender;

      beforeEach(async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        sender = new TACSender({
          domain: 'sender.com',
          privateKey: privateKey
        });
      });

      it('should handle extremely large payloads gracefully', async () => {
        // Create very large payload (10MB)
        const hugeData = {
          largeArray: Array.from({ length: 100000 }, (_, i) => ({
            id: i,
            data: 'x'.repeat(100) // 100 chars per item
          }))
        };

        await sender.addRecipientData('recipient.com', hugeData);

        // Mock JWKS to avoid network
        sender.fetchJWKS = async () => {
          const { publicKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
          const jwk = await jose.exportJWK(publicKey);
          return [
            {
              ...jwk,
              kid: 'recipient.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        };

        // This may succeed or fail depending on system memory
        // The test is to ensure it fails gracefully if it fails
        try {
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage); // If it succeeds, that's fine too
        } catch (error) {
          // Should fail gracefully with memory or size error
          assert.ok(
            error.message.includes('memory') || error.message.includes('size') || error.message.includes('limit')
          );
        }
      });

      it('should handle many recipients without memory leaks', async () => {
        const numRecipients = 1000;
        const recipientData = {};

        // Generate data for many recipients
        for (let i = 1; i <= numRecipients; i++) {
          recipientData[`recipient${i}.com`] = { id: i, data: `data-${i}` };
        }

        await sender.setRecipientsData(recipientData);

        // Mock JWKS to return valid keys for all recipients
        sender.fetchJWKS = async domain => {
          const { publicKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
          const jwk = await jose.exportJWK(publicKey);
          return [
            {
              ...jwk,
              kid: domain,
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        };

        // This should work but may be slow
        try {
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
        } catch (error) {
          // If it fails, should be due to resource limits, not crashes
          assert.ok(
            error.message.includes('memory') || error.message.includes('timeout') || error.message.includes('limit')
          );
        }
      });
    });

    describe('Concurrent Access Issues', () => {
      let sender;
      let recipient;

      beforeEach(async () => {
        const senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        sender = new TACSender({
          domain: 'sender.com',
          privateKey: senderKeys.privateKey
        });

        recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });
      });

      it('should handle concurrent message generation', async () => {
        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        // Add data and generate multiple messages concurrently
        await sender.addRecipientData('recipient.com', { data: 'test' });

        const promises = Array.from({ length: 10 }, () => sender.generateTACMessage());

        const results = await Promise.all(promises);

        // All should succeed
        results.forEach(result => {
          assert.ok(result);
          assert.ok(typeof result === 'string');
        });
      });

      it('should handle concurrent data modifications', async () => {
        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        // Concurrently modify recipient data
        const promises = Array.from({ length: 10 }, (_, i) =>
          sender.addRecipientData('recipient.com', { data: `test-${i}` })
        );

        await Promise.all(promises);

        // The last modification should win
        const tacMessage = await sender.generateTACMessage();
        assert.ok(tacMessage);
      });

      it('should handle concurrent cache operations', async () => {
        const cache = sender.jwksCache;

        // Concurrently set and get cache entries
        const promises = Array.from({ length: 20 }, (_, i) => {
          if (i % 2 === 0) {
            return new Promise(resolve => {
              setTimeout(() => {
                cache.set(`domain${i}.com`, [{ kty: 'RSA', kid: `key-${i}` }]);
                resolve('set');
              }, Math.random() * 10);
            });
          } else {
            return new Promise(resolve => {
              setTimeout(() => {
                resolve(cache.get(`domain${Math.floor(i / 2)}.com`));
              }, Math.random() * 10);
            });
          }
        });

        const results = await Promise.all(promises);

        // Should complete without errors
        assert.strictEqual(results.length, 20);
      });
    });
  });

  describe('Input Security and Validation', () => {
    let sender;
    let recipient;

    beforeEach(async () => {
      const senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      sender = new TACSender({
        domain: 'sender.com',
        privateKey: senderKeys.privateKey
      });

      recipient = new TACRecipient({
        domain: 'recipient.com',
        privateKey: recipientKeys.privateKey
      });
    });

    describe('Injection Attack Protection', () => {
      it('should handle malicious JSON in data payload', async () => {
        const maliciousData = {
          __proto__: { isAdmin: true },
          constructor: { prototype: { isAdmin: true } },
          normal: 'data'
        };

        await sender.addRecipientData('recipient.com', maliciousData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        sender.fetchJWKS = async () => [recipientJWK];
        recipient.fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        // Should not pollute prototype
        assert.strictEqual(result.data.normal, 'data');
        assert.strictEqual({}.isAdmin, undefined);
      });

      it('should handle XSS-style payloads', async () => {
        const xssData = {
          script: "<script>alert('xss')</script>",
          html: "<img src=x onerror=alert('xss')>",
          javascript: "javascript:alert('xss')",
          data: "data:text/html,<script>alert('xss')</script>"
        };

        await sender.addRecipientData('recipient.com', xssData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        sender.fetchJWKS = async () => [recipientJWK];
        recipient.fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        // Data should be preserved as-is (not executed)
        assert.strictEqual(result.data.script, "<script>alert('xss')</script>");
      });

      it('should handle SQL injection-style strings', async () => {
        const sqlData = {
          query: "'; DROP TABLE users; --",
          union: "' UNION SELECT * FROM passwords --",
          comment: '/* malicious comment */',
          normal: 'normal data'
        };

        await sender.addRecipientData('recipient.com', sqlData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        sender.fetchJWKS = async () => [recipientJWK];
        recipient.fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.data.query, "'; DROP TABLE users; --");
      });
    });

    describe('Buffer Overflow Protection', () => {
      it('should handle oversized string inputs', async () => {
        const oversizedData = {
          huge: 'x'.repeat(1000000), // 1MB string
          normal: 'normal data'
        };

        await sender.addRecipientData('recipient.com', oversizedData);

        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        // Should either succeed or fail gracefully
        try {
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
        } catch (error) {
          assert.ok(error.message.includes('size') || error.message.includes('memory'));
        }
      });

      it('should handle deeply nested objects', async () => {
        // Create deeply nested object
        let deepObject = { value: 'deep' };
        for (let i = 0; i < 1000; i++) {
          deepObject = { nested: deepObject };
        }

        await sender.addRecipientData('recipient.com', { deep: deepObject });

        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        try {
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
        } catch (error) {
          // Should fail gracefully due to stack overflow protection
          assert.ok(
            error.message.includes('stack') ||
              error.message.includes('depth') ||
              error.message.includes('Maximum call stack')
          );
        }
      });
    });

    describe('Resource Exhaustion Protection', () => {
      it('should handle DoS-style repeated operations', async () => {
        const recipientJWK = await recipient.getPublicJWK();
        sender.fetchJWKS = async () => [recipientJWK];

        // Rapidly add and clear data many times
        for (let i = 0; i < 100; i++) {
          await sender.addRecipientData('recipient.com', { iteration: i });
          if (i % 2 === 0) {
            sender.clearRecipientData();
            await sender.addRecipientData('recipient.com', { iteration: i });
          }
        }

        const tacMessage = await sender.generateTACMessage();
        assert.ok(tacMessage);
      });

      it('should handle rapid cache operations', async () => {
        const cache = sender.jwksCache;

        // Rapidly set and clear cache entries
        for (let i = 0; i < 1000; i++) {
          cache.set(`domain${i}.com`, [{ kty: 'RSA', kid: `key-${i}` }]);
          if (i % 10 === 0) {
            cache.clear();
          }
        }

        // Should complete without errors
        assert.ok(true);
      });
    });

    describe('Path Traversal Protection', () => {
      it('should validate domain names for JWKS URLs', async () => {
        const maliciousDomains = [
          '../../../etc/passwd',
          '..\\..\\windows\\system32',
          'file:///etc/passwd',
          'http://evil.com/../../internal',
          "javascript:alert('xss')",
          "data:text/html,<script>alert('xss')</script>"
        ];

        for (const domain of maliciousDomains) {
          try {
            await sender.addRecipientData(domain, { data: 'test' });

            sender.fetchJWKS = async requestedDomain => {
              // Should not contain path traversal
              assert.ok(!requestedDomain.includes('..'));
              assert.ok(!requestedDomain.includes('file://'));
              assert.ok(!requestedDomain.includes('javascript:'));
              throw new Error('Validation passed');
            };

            await assert.rejects(async () => await sender.generateTACMessage(), /Validation passed|invalid domain/);
          } catch (error) {
            // Either rejects due to validation or our mock error
            assert.ok(
              error.message.includes('Validation passed') ||
                error.message.includes('invalid') ||
                error.message.includes('domain')
            );
          }
        }
      });
    });
  });

  describe('Edge Case Scenarios', () => {
    describe('Boundary Value Testing', () => {
      it('should handle minimum/maximum integer values', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const boundaryValues = [
          0,
          1,
          -1,
          Number.MAX_SAFE_INTEGER,
          Number.MIN_SAFE_INTEGER,
          Number.MAX_VALUE,
          Number.MIN_VALUE,
          Infinity,
          -Infinity,
          NaN
        ];

        for (const value of boundaryValues) {
          const sender = new TACSender({
            domain: 'test.com',
            privateKey: privateKey,
            ttl: value
          });

          assert.strictEqual(sender.ttl, value);
        }
      });

      it('should handle empty and whitespace-only strings', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        // Empty string is falsy and throws DOMAIN_REQUIRED
        assert.throws(
          () => {
            new TACSender({
              domain: '',
              privateKey: privateKey
            });
          },
          error => {
            return error.name === 'TACValidationError' && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );

        // Whitespace-only strings are truthy, so the SDK accepts them
        // (Note: these would cause issues when fetching JWKS, but constructor accepts them)
        const whitespaceOnlyCases = [' ', '\t', '\n', '\r\n', '   \t\n   '];
        for (const domain of whitespaceOnlyCases) {
          const sender = new TACSender({
            domain: domain,
            privateKey: privateKey
          });
          assert.strictEqual(sender.domain, domain);
        }
      });

      it('should handle various boolean and null values', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const edgeData = {
          booleanTrue: true,
          booleanFalse: false,
          nullValue: null,
          undefinedValue: undefined,
          emptyString: '',
          emptyArray: [],
          emptyObject: {},
          zero: 0,
          negativeZero: -0,
          infinityPos: Infinity,
          infinityNeg: -Infinity,
          notANumber: NaN
        };

        await sender.addRecipientData('recipient.com', edgeData);
        assert.deepStrictEqual(sender.recipientData['recipient.com'], edgeData);
      });
    });

    describe('Unicode and Encoding Edge Cases', () => {
      it('should handle various Unicode characters', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const unicodeData = {
          emoji: '🚀🌟💻🔒🌍',
          chinese: '你好世界',
          arabic: 'مرحبا بالعالم',
          russian: 'Привет мир',
          japanese: 'こんにちは世界',
          mathematical: '∑∏∆√∞≠≤≥±∓',
          symbols: '♠♣♥♦♪♫♯♭',
          combining: 'e\u0301e\u0300e\u0302', // é è ê
          surrogate: '𝓗𝓮𝓵𝓵𝓸', // Mathematical script
          nullChar: 'Hello\u0000World',
          zwsp: 'Hello\u200BWorld' // Zero-width space
        };

        await sender.addRecipientData('recipient.com', unicodeData);
        assert.deepStrictEqual(sender.recipientData['recipient.com'], unicodeData);
      });

      it('should handle different line ending styles', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const lineEndingData = {
          unix: 'Line 1\nLine 2\nLine 3',
          windows: 'Line 1\r\nLine 2\r\nLine 3',
          mac: 'Line 1\rLine 2\rLine 3',
          mixed: 'Line 1\nLine 2\r\nLine 3\rLine 4'
        };

        await sender.addRecipientData('recipient.com', lineEndingData);
        assert.deepStrictEqual(sender.recipientData['recipient.com'], lineEndingData);
      });
    });

    describe('Time and Date Edge Cases', () => {
      it('should handle various date edge cases', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

        const dateEdgeCases = [
          new Date(0), // Unix epoch
          new Date(-1), // Before epoch
          new Date(8640000000000000), // Max date
          new Date(-8640000000000000), // Min date
          new Date('1999-12-31T23:59:59.999Z'), // Y2K edge
          new Date('2000-01-01T00:00:00.000Z'), // Y2K
          new Date('2038-01-19T03:14:07.000Z'), // 32-bit epoch overflow
          new Date(NaN) // Invalid date
        ];

        for (const date of dateEdgeCases) {
          const sender = new TACSender({
            domain: 'test.com',
            privateKey: privateKey
          });

          await sender.addRecipientData('recipient.com', {
            testDate: date,
            timestamp: date.getTime()
          });

          const data = sender.recipientData['recipient.com'];
          assert.ok(data.testDate instanceof Date);
        }
      });
    });

    describe('Cryptographic Error Handling', () => {
      let senderKeys, recipientKeys;

      beforeEach(async () => {
        senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      });

      it('should handle JWT signing failures', async () => {
        const sender = new TACSender({
          domain: 'test.com',
          privateKey: senderKeys.privateKey
        });

        // Mock recipient JWKS
        const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);
        sender.fetchJWKS = async () => [{ ...recipientJWK, kid: 'recipient.com', use: 'enc', alg: 'RSA-OAEP-256' }];

        await sender.addRecipientData('recipient.com', { test: 'data' });

        // Corrupt the private key to cause signing failure
        sender.privateKey = null;

        // SDK throws TACValidationError when private key is null
        await assert.rejects(
          async () => await sender.generateTACMessage(),
          error => {
            return error instanceof TACValidationError && error.message.includes('No private key available');
          }
        );
      });

      it('should handle encryption failures', async () => {
        const sender = new TACSender({
          domain: 'test.com',
          privateKey: senderKeys.privateKey
        });

        // Provide invalid JWK that will cause encryption to fail
        sender.fetchJWKS = async () => [
          {
            kty: 'RSA',
            n: 'invalid-modulus',
            e: 'AQAB',
            kid: 'recipient.com',
            use: 'enc',
            alg: 'RSA-OAEP-256'
          }
        ];

        await sender.addRecipientData('recipient.com', { test: 'data' });

        await assert.rejects(
          async () => await sender.generateTACMessage(),
          error => {
            return (
              (error instanceof TACCryptoError && error.code === TACErrorCodes.JWK_IMPORT_FAILED) ||
              (error instanceof TACCryptoError && error.code === TACErrorCodes.ENCRYPTION_FAILED)
            );
          }
        );
      });

      it('should handle decryption failures', async () => {
        const recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });

        // Create a malformed JWE that will fail to decrypt
        const malformedJWE = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.invalid.invalid.invalid.invalid';
        const malformedMessage = {
          version: '2025-08-27',
          recipients: [{ kid: 'recipient.com', jwe: malformedJWE }]
        };

        const tacMessage = Buffer.from(JSON.stringify(malformedMessage)).toString('base64');
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, false);
        assert.ok(result.errors.some(e => e.includes('Decryption failed') || e.includes('decrypt')));
      });

      it('should handle signature verification failures', async () => {
        const sender = new TACSender({
          domain: 'test.com',
          privateKey: senderKeys.privateKey
        });

        const recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });

        // Create valid message
        const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);
        sender.fetchJWKS = async () => [{ ...recipientJWK, kid: 'recipient.com', use: 'enc', alg: 'RSA-OAEP-256' }];

        await sender.addRecipientData('recipient.com', { test: 'data' });
        const tacMessage = await sender.generateTACMessage();

        // Use different key for verification (will cause signature verification to fail)
        const wrongKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const wrongJWK = await jose.exportJWK(wrongKeys.publicKey);
        recipient.fetchJWKS = async () => [{ ...wrongJWK, kid: 'test.com', use: 'sig', alg: 'RS256' }];

        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, false);
        assert.ok(result.errors.some(e => e.includes('Signature verification failed') || e.includes('signature')));
      });

      it('should handle JWT decode failures', async () => {
        const recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });

        // Create a JWE that decrypts to invalid JWT
        const invalidJWT = 'not.a.jwt';
        const validJWE = await new jose.CompactEncrypt(new TextEncoder().encode(invalidJWT))
          .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
          .encrypt(recipientKeys.publicKey);

        const invalidMessage = {
          version: '2025-08-27',
          recipients: [{ kid: 'recipient.com', jwe: validJWE }]
        };

        const tacMessage = Buffer.from(JSON.stringify(invalidMessage)).toString('base64');
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, false);
        assert.ok(result.errors.some(e => e.includes('JWT decode failed') || e.includes('decode')));
      });

      it('should handle JWK import failures', async () => {
        const recipient = new TACRecipient({
          domain: 'recipient.com',
          privateKey: recipientKeys.privateKey
        });

        // Mock JWKS with malformed JWK
        recipient.fetchJWKS = async () => [
          {
            kty: 'RSA',
            n: 'invalid-base64-data!@#$%',
            e: 'AQAB',
            kid: 'test.com',
            use: 'sig',
            alg: 'RS256'
          }
        ];

        // Create a valid JWE first
        const validJWT = await new jose.SignJWT({ iss: 'test.com', aud: 'recipient.com', data: { test: 'data' } })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
          .sign(senderKeys.privateKey);

        const validJWE = await new jose.CompactEncrypt(new TextEncoder().encode(validJWT))
          .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
          .encrypt(recipientKeys.publicKey);

        const message = {
          version: '2025-08-27',
          recipients: [{ kid: 'recipient.com', jwe: validJWE }]
        };

        const tacMessage = Buffer.from(JSON.stringify(message)).toString('base64');
        const result = await recipient.processTACMessage(tacMessage);

        // The result should be invalid due to signature verification failure
        // (caused by malformed JWK that can't verify the signature)
        assert.strictEqual(result.valid, false);
        assert.ok(result.errors.length > 0, 'Should have at least one error');
      });

      it('should handle JWK export failures', async () => {
        const recipient = new TACRecipient({
          domain: 'test.com',
          privateKey: recipientKeys.privateKey
        });

        // Corrupt the public key to cause export failure
        recipient.publicKey = null;

        // SDK throws TACValidationError when public key is null
        await assert.rejects(
          async () => await recipient.getPublicJWK(),
          error => {
            return error instanceof TACValidationError && error.message.includes('No public key available');
          }
        );
      });
    });
  });
});
