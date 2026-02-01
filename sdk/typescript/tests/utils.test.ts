import { describe, it } from "node:test";
import assert from "node:assert";
import * as jose from "jose";
import {
  getUserAgent,
  getKeyType,
  getAlgorithmForKey,
  findEncryptionKey,
  findSigningKey,
  publicKeyToJWK,
} from "../src/utils.js";
import { SCHEMA_VERSION, SDK_VERSION, SDK_LANGUAGE } from "../src/version.js";

describe("Utility Functions", () => {
  describe("getUserAgent", () => {
    it("should return correct User-Agent format", () => {
      const userAgent = getUserAgent();

      // Should match format: TAC-Protocol/version (language/sdk-version)
      const escapedSchema = SCHEMA_VERSION.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const escapedSDKVersion = SDK_VERSION.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const expectedPattern = new RegExp(`^TAC-Protocol/${escapedSchema} \\(${SDK_LANGUAGE}/${escapedSDKVersion}\\)$`);
      assert.match(userAgent, expectedPattern);
    });

    it("should include correct version information", () => {
      const userAgent = getUserAgent();
      assert.ok(userAgent.includes(SCHEMA_VERSION));
      assert.ok(userAgent.includes(SDK_VERSION));
      assert.ok(userAgent.includes(SDK_LANGUAGE));
    });

    it("should be consistent across multiple calls", () => {
      const userAgent1 = getUserAgent();
      const userAgent2 = getUserAgent();
      assert.strictEqual(userAgent1, userAgent2);
    });

    it("should return only TAC-Protocol when hideVersion is true", () => {
      const userAgent = getUserAgent({ hideVersion: true });
      assert.strictEqual(userAgent, "TAC-Protocol");
    });

    it("should include version details when hideVersion is false", () => {
      const userAgent = getUserAgent({ hideVersion: false });
      assert.ok(userAgent.includes(SCHEMA_VERSION));
      assert.ok(userAgent.includes(SDK_VERSION));
    });

    it("should include version details by default", () => {
      const userAgent = getUserAgent();
      const userAgentExplicit = getUserAgent({ hideVersion: false });
      assert.strictEqual(userAgent, userAgentExplicit);
    });
  });

  describe("getKeyType", () => {
    it("should detect RSA keys", async () => {
      const { privateKey } = await jose.generateKeyPair("RS256", {
        modulusLength: 2048,
      });

      const keyType = getKeyType(privateKey as any);
      assert.strictEqual(keyType, "RSA");
    });

    it("should throw for unsupported key types", () => {
      const invalidKey = { asymmetricKeyType: "DSA" };
      assert.throws(() => {
        getKeyType(invalidKey as any);
      }, /Unsupported key type: DSA/);
    });
  });

  describe("getAlgorithmForKey", () => {
    it("should return correct signing algorithms for RSA keys", async () => {
      const { privateKey } = await jose.generateKeyPair("RS256", {
        modulusLength: 2048,
      });

      const algorithm = getAlgorithmForKey(privateKey as any, "sig");
      // Note: The actual implementation defaults to RS256, not size-based selection
      assert.strictEqual(algorithm, "RS256");
    });

    it("should return correct encryption algorithms for RSA keys", async () => {
      const { privateKey } = await jose.generateKeyPair("RS256", {
        modulusLength: 2048,
      });

      const algorithm = getAlgorithmForKey(privateKey as any, "enc");
      assert.strictEqual(algorithm, "RSA-OAEP-256");
    });

    it("should default to signing algorithms when use not specified", async () => {
      const { privateKey } = await jose.generateKeyPair("RS256");

      const algorithm = getAlgorithmForKey(privateKey as any);
      assert.strictEqual(algorithm, "RS256");
    });
  });

  describe("findEncryptionKey", () => {
    it("should find RSA encryption key", () => {
      const keys = [
        { kty: "RSA", use: "sig", kid: "sig-key" },
        { kty: "RSA", use: "enc", kid: "enc-key", n: "test", e: "AQAB" },
        { kty: "EC", use: "sig", kid: "ec-key" },
      ] as any[];

      const encKey = findEncryptionKey(keys);
      assert.strictEqual(encKey?.kid, "enc-key");
      assert.strictEqual(encKey?.use, "enc");
    });

    it("should find RSA key without use field (dual-purpose)", () => {
      const keys = [
        { kty: "EC", use: "sig" },
        { kty: "RSA", kid: "dual-key", n: "test", e: "AQAB" }, // No use field
        { kty: "RSA", use: "sig" },
      ] as any[];

      const encKey = findEncryptionKey(keys);
      assert.strictEqual(encKey?.kid, "dual-key");
      assert.strictEqual(encKey?.kty, "RSA");
    });

    it("should return undefined when no encryption key found", () => {
      const keys = [
        { kty: "RSA", use: "sig" },
        { kty: "EC", use: "sig" },
      ] as any[];

      const encKey = findEncryptionKey(keys);
      assert.strictEqual(encKey, undefined);
    });

    it("should handle empty keys array", () => {
      const encKey = findEncryptionKey([]);
      assert.strictEqual(encKey, undefined);
    });
  });

  describe("findSigningKey", () => {
    it("should find signing key by kid", () => {
      const keys = [
        { kty: "RSA", kid: "key-1", use: "enc" },
        { kty: "RSA", kid: "key-2", use: "sig" },
        { kty: "EC", kid: "key-3", use: "sig" },
      ] as any[];

      const sigKey = findSigningKey(keys, "key-2");
      assert.strictEqual(sigKey?.kid, "key-2");
      assert.strictEqual(sigKey?.use, "sig");
    });

    it("should find first signing key when no kid specified", () => {
      const keys = [
        { kty: "RSA", kid: "enc-key", use: "enc" },
        { kty: "RSA", kid: "sig-key-1", use: "sig" },
        { kty: "EC", kid: "sig-key-2", use: "sig" },
      ] as any[];

      const sigKey = findSigningKey(keys);
      assert.strictEqual(sigKey?.kid, "sig-key-1");
    });

    it("should find key without use field (dual-purpose)", () => {
      const keys = [
        { kty: "RSA", kid: "enc-only", use: "enc" },
        { kty: "RSA", kid: "dual-key" }, // No use field = can be used for signing
        { kty: "RSA", kid: "sig-only", use: "sig" },
      ] as any[];

      const sigKey = findSigningKey(keys, "dual-key");
      assert.strictEqual(sigKey?.kid, "dual-key");
    });

    it("should return first available signing key when specific key not found", () => {
      const keys = [{ kty: "RSA", kid: "key-1", use: "sig" }] as any[];

      // When a specific key is not found, the function returns the first available signing key
      const sigKey = findSigningKey(keys, "non-existent");
      assert.strictEqual(sigKey?.kid, "key-1");
    });

    it("should handle empty keys array", () => {
      const sigKey = findSigningKey([], "any-key");
      assert.strictEqual(sigKey, undefined);
    });
  });

  describe("publicKeyToJWK", () => {
    it("should convert RSA public key to JWK", async () => {
      const { publicKey } = await jose.generateKeyPair("RS256", {
        modulusLength: 2048,
      });

      const jwk = await publicKeyToJWK(publicKey);

      assert.strictEqual(jwk.kty, "RSA");
      assert.strictEqual(jwk.alg, "RS256");
      assert.ok(jwk.kid);
      assert.ok(jwk.n);
      assert.strictEqual(jwk.e, "AQAB");
    });

    it("should generate consistent key IDs", async () => {
      const { publicKey } = await jose.generateKeyPair("RS256");

      const jwk1 = await publicKeyToJWK(publicKey);
      const jwk2 = await publicKeyToJWK(publicKey);

      assert.strictEqual(jwk1.kid, jwk2.kid);
    });

    it("should accept custom key ID", async () => {
      const { publicKey } = await jose.generateKeyPair("RS256");
      const customKid = "custom-key-id";

      const jwk = await publicKeyToJWK(publicKey, customKid);

      assert.strictEqual(jwk.kid, customKid);
    });

    it("should throw for null/undefined input", async () => {
      await assert.rejects(async () => {
        await publicKeyToJWK(null as any);
      }, /No public key provided/);
    });
  });
});
