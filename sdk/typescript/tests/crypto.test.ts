import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import * as jose from "jose";
import TACSender from "../src/sender.js";

describe("Cryptographic Operations", () => {
  describe("Key Management Tests", () => {
    describe("Valid Key Types", () => {
      it("should support RSA 2048-bit keys", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        assert.strictEqual(sender.signingAlgorithm, "RS256");
        // Note: asymmetricKeySize may not be available on all key types
      });

      it("should support RSA 3072-bit keys", async () => {
        const { privateKey } = await jose.generateKeyPair("RS384", {
          modulusLength: 3072,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        assert.strictEqual(sender.signingAlgorithm, "RS256"); // Implementation defaults to RS256
        // Note: asymmetricKeySize may not be available on all key types
      });

      it("should support RSA 4096-bit keys", async () => {
        const { privateKey } = await jose.generateKeyPair("RS512", {
          modulusLength: 4096,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        assert.strictEqual(sender.signingAlgorithm, "RS256"); // Implementation defaults to RS256
        // Note: asymmetricKeySize may not be available on all key types
      });
    });

    describe("Invalid Key Types", () => {
      it("should reject unsupported key types gracefully", () => {
        // Create an Ed25519 key (unsupported)
        const ed25519Key = crypto.generateKeyPairSync("ed25519");

        // Should throw an error when trying to use unsupported key type
        assert.throws(
          () => {
            new TACSender({
              domain: "test.com",
              privateKey: ed25519Key.privateKey,
            });
          },
          {
            name: "TACCryptoError",
            message: /TAC Protocol requires RSA keys/,
          }
        );
      });

      it("should reject EC keys", async () => {
        // EC keys are not supported
        const { privateKey } = await jose.generateKeyPair("ES256");

        assert.throws(() => {
          new TACSender({
            domain: "test.com",
            privateKey: privateKey as any,
          });
        }, /TAC Protocol requires RSA keys/);
      });

      it("should reject DSA keys", () => {
        // DSA keys are not supported
        const dsaKey = crypto.generateKeyPairSync("dsa", {
          modulusLength: 2048,
          divisorLength: 256,
        });

        assert.throws(() => {
          new TACSender({
            domain: "test.com",
            privateKey: dsaKey.privateKey,
          });
        }, /TAC Protocol requires RSA keys/);
      });

      it("should handle invalid PEM strings gracefully", () => {
        const invalidPem = "-----BEGIN PRIVATE KEY-----\ninvalid key data\n-----END PRIVATE KEY-----";

        assert.throws(
          () => {
            new TACSender({
              domain: "test.com",
              privateKey: invalidPem,
            });
          },
          {
            name: "TACCryptoError",
            message: /Invalid key data/,
          }
        );
      });

      it("should handle empty/null keys gracefully", () => {
        assert.throws(
          () => {
            new TACSender({
              domain: "test.com",
              privateKey: "",
            });
          },
          {
            name: "TACValidationError",
            message: /privateKey is required/,
          }
        );
      });
    });

    describe("Key ID Generation", () => {
      it("should generate consistent key IDs for same key", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender1 = new TACSender({
          domain: "test.com",
          privateKey: privateKey,
        });

        const sender2 = new TACSender({
          domain: "other.com",
          privateKey: privateKey,
        });

        const keyId1 = sender1.generateKeyId();
        const keyId2 = sender2.generateKeyId();

        // Same key should generate same key ID regardless of domain
        assert.strictEqual(keyId1, keyId2);
        assert.match(keyId1, /^[A-Za-z0-9_-]+$/); // Base64URL format
        assert.ok(keyId1.length > 0);
      });

      it("should generate different key IDs for different keys", async () => {
        const { privateKey: key1 } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });
        const { privateKey: key2 } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender1 = new TACSender({
          domain: "test.com",
          privateKey: key1 as any,
        });

        const sender2 = new TACSender({
          domain: "test.com",
          privateKey: key2 as any,
        });

        const keyId1 = sender1.generateKeyId();
        const keyId2 = sender2.generateKeyId();

        // Different keys should generate different key IDs
        assert.notStrictEqual(keyId1, keyId2);
      });

      it("should generate key ID without requiring public key manually", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        // Should be able to generate key ID immediately after construction
        const keyId = sender.generateKeyId();
        assert.ok(keyId);
        assert.match(keyId, /^[A-Za-z0-9_-]+$/);
      });
    });

    describe("JWK Export", () => {
      it("should export RSA public key as JWK", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        const jwk = await sender.getPublicJWK();

        assert.strictEqual(jwk.kty, "RSA");
        assert.ok(jwk.n); // Modulus
        assert.ok(jwk.e); // Exponent
        assert.ok(jwk.kid); // Key ID
        assert.ok(jwk.alg); // Algorithm
        assert.ok(!(jwk as any).d); // Should not include private exponent
      });

      it("should include key ID in exported JWK", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        const jwk = await sender.getPublicJWK();
        const keyId = sender.generateKeyId();

        assert.strictEqual(jwk.kid, keyId);
      });
    });

    describe("Algorithm Selection", () => {
      it("should select correct signing algorithm for RSA keys", async () => {
        const { privateKey } = await jose.generateKeyPair("RS256", {
          modulusLength: 2048,
        });

        const sender = new TACSender({
          domain: "test.com",
          privateKey: privateKey as any,
        });

        assert.strictEqual(sender.signingAlgorithm, "RS256");
      });
    });
  });

  describe("String Key Support", () => {
    it("should support PEM-encoded RSA private keys", async () => {
      // Generate a key pair and export private key as PEM
      const { privateKey } = await jose.generateKeyPair("RS256", {
        modulusLength: 2048,
      });

      const pemPrivateKey = (privateKey as any).export({
        type: "pkcs8",
        format: "pem",
      }) as string;

      // Should be able to construct sender with PEM string
      const sender = new TACSender({
        domain: "test.com",
        privateKey: pemPrivateKey,
      });

      assert.strictEqual(sender.signingAlgorithm, "RS256");

      // Should be able to generate key ID
      const keyId = sender.generateKeyId();
      assert.ok(keyId);
    });

    it("should handle malformed PEM keys gracefully", () => {
      const malformedPem = "-----BEGIN PRIVATE KEY-----\nthis is not a valid key\n-----END PRIVATE KEY-----";

      assert.throws(
        () => {
          new TACSender({
            domain: "test.com",
            privateKey: malformedPem,
          });
        },
        {
          name: "TACCryptoError",
          message: /Invalid key data/,
        }
      );
    });
  });
});
