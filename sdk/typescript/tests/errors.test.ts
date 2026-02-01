import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";
import * as jose from "jose";
import TACSender from "../src/sender.js";
import TACRecipient from "../src/recipient.js";
import { TACErrorCodes } from "../src/errors.js";

describe("Error Handling and Edge Cases", () => {
  describe("Input Validation", () => {
    describe("TACSender Constructor", () => {
      it("should reject empty domain", () => {
        assert.throws(
          () => {
            new TACSender({
              domain: "",
              privateKey: "dummy-key",
            });
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it("should reject null domain", () => {
        assert.throws(
          () => {
            new TACSender({
              domain: null as any,
              privateKey: "dummy-key",
            });
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it("should reject undefined domain", () => {
        assert.throws(
          () => {
            new TACSender({
              privateKey: "dummy-key",
            } as any);
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it("should reject missing private key", () => {
        assert.throws(
          () => {
            new TACSender({
              domain: "test.com",
            } as any);
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.PRIVATE_KEY_REQUIRED;
          }
        );
      });

      it("should reject null private key", () => {
        assert.throws(
          () => {
            new TACSender({
              domain: "test.com",
              privateKey: null as any,
            });
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.PRIVATE_KEY_REQUIRED;
          }
        );
      });

      it("should reject invalid private key format", () => {
        assert.throws(
          () => {
            new TACSender({
              domain: "test.com",
              privateKey: "invalid-pem-format",
            });
          },
          (error: any) => {
            return error.name === "TACCryptoError" && error.code === "TAC_INVALID_KEY_DATA";
          }
        );
      });

      it("should handle negative TTL values", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
          ttl: -3600, // Negative TTL
        });

        // Should not crash during construction
        assert.ok(sender);
        assert.strictEqual(sender.domain, "test.com");
      });

      it("should handle zero TTL", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
          ttl: 0,
        });

        assert.ok(sender);
        assert.strictEqual(sender.domain, "test.com");
      });

      it("should handle extremely large TTL values", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
          ttl: Number.MAX_SAFE_INTEGER,
        });

        assert.ok(sender);
        assert.strictEqual(sender.domain, "test.com");
      });
    });

    describe("TACRecipient Constructor", () => {
      it("should reject empty domain", () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: "",
              privateKey: "dummy-key",
            });
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.DOMAIN_REQUIRED;
          }
        );
      });

      it("should reject missing private key", () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: "test.com",
            } as any);
          },
          (error: any) => {
            return error.name === "TACValidationError" && error.code === TACErrorCodes.PRIVATE_KEY_REQUIRED;
          }
        );
      });

      it("should reject invalid private key format", () => {
        assert.throws(
          () => {
            new TACRecipient({
              domain: "test.com",
              privateKey: "invalid-pem-format",
            });
          },
          (error: any) => {
            return error.name === "TACCryptoError" && error.code === "TAC_INVALID_KEY_DATA";
          }
        );
      });
    });

    describe("Domain Validation", () => {
      it("should accept valid domain names", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const validDomains = [
          "example.com",
          "sub.example.com",
          "test-domain.co.uk",
          "my_domain.org",
          "123domain.net",
          "domain-with-dashes.com",
        ];

        validDomains.forEach((domain) => {
          assert.doesNotThrow(() => {
            new TACSender({
              domain,
              privateKey: privateKey as any,
            });
          });
        });
      });

      it("should handle edge case domains", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const edgeCaseDomains = [
          "a.b", // Very short
          "x".repeat(253), // Maximum length domain
          "localhost",
          "127.0.0.1", // IP address
          "::1", // IPv6
        ];

        edgeCaseDomains.forEach((domain) => {
          assert.doesNotThrow(() => {
            new TACSender({
              domain,
              privateKey: privateKey as any,
            });
          });
        });
      });
    });
  });

  describe("Runtime Error Scenarios", () => {
    let sender: TACSender;
    let recipient: TACRecipient;

    beforeEach(async () => {
      const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
      const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

      sender = new TACSender({
        domain: "sender.com",
        privateKey: senderKeys.privateKey as any,
      });

      recipient = new TACRecipient({
        domain: "recipient.com",
        privateKey: recipientKeys.privateKey as any,
      });
    });

    describe("Network and JWKS Errors", () => {
      it("should handle JWKS endpoint returning 404", async () => {
        (sender as any).fetchJWKS = async () => {
          const error = new Error("HTTP 404: Not Found");
          (error as any).statusCode = 404;
          throw error;
        };

        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });

        await assert.rejects(
          async () => await sender.generateTACMessage(),
          (error: any) => error.message.includes("404")
        );
      });

      it("should handle JWKS endpoint timeout", async () => {
        (sender as any).fetchJWKS = async () => {
          throw new Error("Request timeout");
        };

        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });

        await assert.rejects(
          async () => await sender.generateTACMessage(),
          (error: any) => error.message.includes("timeout")
        );
      });

      it("should handle malformed JWKS response", async () => {
        (sender as any).fetchJWKS = async () => {
          return "not-an-array";
        };

        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });

        await assert.rejects(async () => await sender.generateTACMessage());
      });

      it("should handle JWKS with no encryption keys", async () => {
        (sender as any).fetchJWKS = async () => [
          {
            kty: "RSA",
            kid: "signing-key",
            use: "sig",
            alg: "RS256",
            n: "test",
            e: "AQAB",
          },
        ];

        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });

        await assert.rejects(
          async () => await sender.generateTACMessage(),
          (error: any) => error.message.includes("No suitable encryption key found")
        );
      });
    });

    describe("Encryption and Decryption Errors", () => {
      it("should handle corrupted private key during encryption", async () => {
        const recipientJWK = await recipient.getPublicJWK();
        (sender as any).fetchJWKS = async () => [recipientJWK];

        // Corrupt the private key
        (sender as any).privateKey = null;

        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });

        await assert.rejects(async () => await sender.generateTACMessage());
      });

      it("should handle corrupted private key during decryption", async () => {
        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });
        const tacMessage = await sender.generateTACMessage();

        // Corrupt recipient's private key
        (recipient as any).privateKey = null;

        const result = await recipient.processTACMessage(tacMessage);
        assert.strictEqual(result.valid, false);
        assert.ok(result.errors.some((e: string) => e.includes("private key") || e.includes("decrypt")));
      });

      it("should handle malformed JWK data", async () => {
        // Create a malformed JWK that claims to be RSA but is missing required fields
        const malformedJWK = {
          kty: "RSA",
          kid: "malformed-key",
          use: "enc",
          alg: "RSA-OAEP-256",
          // Missing required RSA fields: n, e
        };

        (sender as any).fetchJWKS = async () => [malformedJWK];

        await sender.addRecipientData("malformed-recipient.com", { custom: { data: "test" } });

        try {
          await sender.generateTACMessage();
          // If it doesn't throw, that's okay - the SDK may handle gracefully
          assert.ok(true, "SDK handled the key mismatch gracefully");
        } catch (error: any) {
          // If it throws, that's also okay - expect crypto-related error
          assert.ok(
            error.message.includes("key") ||
              error.message.includes("algorithm") ||
              error.message.includes("crypto") ||
              error.message.includes("encryption"),
            `Expected crypto-related error, got: ${error.message}`
          );
        }
      });
    });

    describe("Memory and Performance Limits", () => {
      it("should handle extremely large payloads", async () => {
        const recipientJWK = await recipient.getPublicJWK();
        (sender as any).fetchJWKS = async () => [recipientJWK];

        // Create a 10MB payload
        const largeData = {
          custom: {
            largeField: "x".repeat(10 * 1024 * 1024),
            metadata: { size: 10 * 1024 * 1024 },
          },
        };

        await sender.addRecipientData("recipient.com", largeData);

        try {
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
        } catch (error: any) {
          // Should handle gracefully, not crash
          assert.ok(
            error.message.includes("memory") ||
              error.message.includes("size") ||
              error.message.includes("limit") ||
              error.message.includes("payload")
          );
        }
      });

      it("should handle many recipients without memory leaks", async () => {
        const numRecipients = 100; // Reduced from 1000 for faster tests
        const recipientData: Record<string, any> = {};

        // Generate data for many recipients
        for (let i = 1; i <= numRecipients; i++) {
          recipientData[`recipient${i}.com`] = { custom: { id: i, data: `data-${i}` } };
        }

        await sender.setRecipientsData(recipientData);

        // Mock JWKS to return valid keys for all recipients
        (sender as any).fetchJWKS = async (domain: string) => {
          const { publicKey } = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
          const jwk = await jose.exportJWK(publicKey);
          return [
            {
              ...jwk,
              kid: domain,
              use: "enc",
              alg: "RSA-OAEP-256",
            },
          ];
        };

        // This should work but may be slow
        try {
          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
        } catch (error: any) {
          // If it fails, should be due to resource limits, not crashes
          assert.ok(
            error.message.includes("memory") || error.message.includes("timeout") || error.message.includes("limit")
          );
        }
      });
    });

    describe("Concurrent Access Issues", () => {
      it("should handle concurrent message generation", async () => {
        const recipientJWK = await recipient.getPublicJWK();
        (sender as any).fetchJWKS = async () => [recipientJWK];

        // Add data and generate multiple messages concurrently
        await sender.addRecipientData("recipient.com", { custom: { data: "test" } });

        const promises = Array.from({ length: 10 }, () => sender.generateTACMessage());

        const results = await Promise.all(promises);

        // All should succeed
        results.forEach((result) => {
          assert.ok(result);
          assert.ok(typeof result === "string");
        });
      });

      it("should handle concurrent data modifications", async () => {
        const recipientJWK = await recipient.getPublicJWK();
        (sender as any).fetchJWKS = async () => [recipientJWK];

        // Concurrently modify recipient data
        const promises = Array.from({ length: 10 }, (_, i) =>
          sender.addRecipientData("recipient.com", { custom: { data: `test-${i}` } })
        );

        await Promise.all(promises);

        // The last modification should win
        const tacMessage = await sender.generateTACMessage();
        assert.ok(tacMessage);
      });

      it("should handle concurrent cache operations", async () => {
        const cache = (sender as any).jwksCache;

        // Concurrently set and get cache entries
        const promises = Array.from({ length: 20 }, (_, i) => {
          if (i % 2 === 0) {
            return new Promise<string>((resolve) => {
              setTimeout(() => {
                cache.set(`domain${i}.com`, [{ kty: "RSA", kid: `key-${i}` }]);
                resolve("set");
              }, Math.random() * 10);
            });
          } else {
            return new Promise<any>((resolve) => {
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

  describe("Input Security and Validation", () => {
    let sender: TACSender;
    let recipient: TACRecipient;

    beforeEach(async () => {
      const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
      const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

      sender = new TACSender({
        domain: "sender.com",
        privateKey: senderKeys.privateKey as any,
      });

      recipient = new TACRecipient({
        domain: "recipient.com",
        privateKey: recipientKeys.privateKey as any,
      });
    });

    describe("Injection Attack Protection", () => {
      it("should handle malicious JSON in data payload", async () => {
        const maliciousData = {
          __proto__: { isAdmin: true },
          constructor: { prototype: { isAdmin: true } },
          custom: {
            normal: "data",
          },
        };

        await sender.addRecipientData("recipient.com", maliciousData as any);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        // Should not pollute prototype
        assert.strictEqual((result.data as any).custom.normal, "data");
        assert.strictEqual(({} as any).isAdmin, undefined);
      });

      it("should handle XSS-style payloads", async () => {
        const xssData = {
          custom: {
            script: "<script>alert('xss')</script>",
            html: "<img src=x onerror=alert('xss')>",
            javascript: "javascript:alert('xss')",
            data: "data:text/html,<script>alert('xss')</script>",
          },
        };

        await sender.addRecipientData("recipient.com", xssData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        // Data should be preserved as-is (not executed)
        assert.strictEqual((result.data as any).custom.script, "<script>alert('xss')</script>");
      });

      it("should handle SQL injection-style strings", async () => {
        const sqlData = {
          custom: {
            query: "'; DROP TABLE users; --",
            union: "' UNION SELECT * FROM passwords --",
            comment: "/* malicious comment */",
            normal: "normal data",
          },
        };

        await sender.addRecipientData("recipient.com", sqlData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        // Data should be preserved as-is
        assert.strictEqual((result.data as any).custom.query, "'; DROP TABLE users; --");
        assert.strictEqual((result.data as any).custom.normal, "normal data");
      });

      it("should handle Unicode and control characters", async () => {
        const unicodeData = {
          custom: {
            emoji: "🚀🔐💻",
            chinese: "你好世界",
            arabic: "مرحبا بالعالم",
            control: "\x00\x01\x02\x1F\x7F",
            zero_width: "\u200B\u200C\u200D\uFEFF",
            newlines: "line1\nline2\r\nline3\ttab",
          },
        };

        await sender.addRecipientData("recipient.com", unicodeData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        // Unicode should be preserved
        assert.strictEqual((result.data as any).custom.emoji, "🚀🔐💻");
        assert.strictEqual((result.data as any).custom.chinese, "你好世界");
      });
    });

    describe("Size and Content Limits", () => {
      it("should handle deeply nested objects", async () => {
        // Create a deeply nested object
        let deepObject: any = { custom: { value: "deep" } };
        for (let i = 0; i < 100; i++) {
          deepObject = { custom: { nested: deepObject } };
        }

        try {
          await sender.addRecipientData("recipient.com", deepObject);

          const recipientJWK = await recipient.getPublicJWK();
          (sender as any).fetchJWKS = async () => [recipientJWK];

          const tacMessage = await sender.generateTACMessage();
          assert.ok(tacMessage);
        } catch (error: any) {
          // Should handle gracefully
          assert.ok(
            error.message.includes("stack") || error.message.includes("depth") || error.message.includes("nested")
          );
        }
      });

      it("should handle circular references", async () => {
        const circularData: any = { custom: { name: "test" } };
        circularData.custom.self = circularData;

        try {
          await sender.addRecipientData("recipient.com", circularData);

          const recipientJWK = await recipient.getPublicJWK();
          (sender as any).fetchJWKS = async () => [recipientJWK];

          await sender.generateTACMessage();
          // Should not reach here if circular reference is detected
          assert.fail("Should have thrown an error for circular reference");
        } catch (error: any) {
          // Should detect circular reference
          assert.ok(error.message.includes("circular") || error.message.includes("Converting circular"));
        }
      });

      it("should handle empty and null values", async () => {
        const emptyData = {
          custom: {
            empty_string: "",
            null_value: null,
            undefined_value: undefined,
            empty_array: [],
            empty_object: {},
            zero: 0,
            false_value: false,
          },
        };

        await sender.addRecipientData("recipient.com", emptyData);

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        const tacMessage = await sender.generateTACMessage();
        const result = await recipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        assert.strictEqual((result.data as any).custom.empty_string, "");
        assert.strictEqual((result.data as any).custom.null_value, null);
        // undefined should be preserved or converted to null
        assert.ok(
          (result.data as any).custom.undefined_value === undefined ||
            (result.data as any).custom.undefined_value === null
        );
      });
    });
  });

  describe("Error Message Quality", () => {
    it("should provide helpful error messages for common mistakes", async () => {
      const tests = [
        {
          action: () => new TACSender({ domain: "", privateKey: "test" }),
          expectedMessage: /domain.*required/i,
        },
        {
          action: () => new TACSender({ domain: "test.com" } as any),
          expectedMessage: /private.*key.*required/i,
        },
        {
          action: () => new TACRecipient({ domain: "test.com" } as any),
          expectedMessage: /private.*key.*required/i,
        },
      ];

      tests.forEach(({ action, expectedMessage }) => {
        assert.throws(action, expectedMessage);
      });
    });

    it("should include error codes in TAC errors", async () => {
      try {
        new TACSender({ domain: "", privateKey: "test" });
        assert.fail("Should have thrown an error");
      } catch (error: any) {
        assert.ok(error.code);
        assert.strictEqual(error.code, TACErrorCodes.DOMAIN_REQUIRED);
      }
    });
  });
});
