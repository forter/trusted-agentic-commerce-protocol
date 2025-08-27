import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import * as jose from "jose";
import TACSender from "./sender.js";
import TACRecipient from "./recipient.js";
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findEncryptionKey,
  findSigningKey,
} from "./utils.js";

// Helper function to generate RSA key pairs for testing
async function generateRSAKeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair("RS256", {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

describe("Trusted Agentic Commerce Protocol - JavaScript SDK", () => {
  describe("TACSender", () => {
    let senderKeys;
    let sender;

    beforeEach(async () => {
      senderKeys = await generateRSAKeyPair();
      sender = new TACSender({
        domain: "agent.example.com",
        privateKey: senderKeys.privateKey,
        ttl: 3600,
      });
    });

    it("should require domain and privateKey in constructor", async () => {
      assert.throws(() => new TACSender({}), /domain is required/);
      assert.throws(
        () => new TACSender({ domain: "test.com" }),
        /privateKey is required/
      );
    });

    it("should initialize with RSA keys and derive public key", () => {
      assert.strictEqual(sender.domain, "agent.example.com");
      assert.ok(sender.privateKey);
      assert.ok(sender.publicKey);
      assert.strictEqual(sender.privateKey.asymmetricKeyType, "rsa");
      assert.strictEqual(sender.publicKey.asymmetricKeyType, "rsa");
    });

    it("should initialize with EC keys", async () => {
      const ecKeys = await jose.generateKeyPair("ES256");
      const sender = new TACSender({
        domain: "agent.example.com",
        privateKey: ecKeys.privateKey,
      });

      assert.strictEqual(sender.domain, "agent.example.com");
      assert.strictEqual(sender.privateKey.asymmetricKeyType, "ec");
      assert.strictEqual(sender.publicKey.asymmetricKeyType, "ec");
      assert.strictEqual(sender.keyType, "EC");
      assert.strictEqual(sender.signingAlgorithm, "ES256");
    });

    it("should generate consistent key IDs", () => {
      const keyId1 = sender.generateKeyId();
      const keyId2 = sender.generateKeyId();

      assert.strictEqual(keyId1, keyId2);
      assert.match(keyId1, /^[A-Za-z0-9_-]+$/); // Base64url format
    });

    it("should add recipient data", async () => {
      await sender.addRecipientData("merchant.com", {
        user: { email: { address: "test@example.com" } },
      });

      assert.deepStrictEqual(sender.recipientData["merchant.com"], {
        user: { email: { address: "test@example.com" } },
      });
    });

    it("should set recipients data (clearing existing)", async () => {
      // Add some initial data
      await sender.addRecipientData("old.com", { test: "data" });

      // Set new data (should clear old)
      await sender.setRecipientsData({
        "merchant.com": { user: { intent: "Buy shoes" } },
        "forter.com": { session: { ipAddress: "1.2.3.4" } },
      });

      assert.strictEqual(Object.keys(sender.recipientData).length, 2);
      assert.deepStrictEqual(sender.recipientData["merchant.com"], {
        user: { intent: "Buy shoes" },
      });
      assert.deepStrictEqual(sender.recipientData["forter.com"], {
        session: { ipAddress: "1.2.3.4" },
      });
      assert.strictEqual(sender.recipientData["old.com"], undefined);
    });

    it("should clear recipient data", async () => {
      await sender.addRecipientData("test.com", { data: "test" });
      sender.clearRecipientData();

      assert.deepStrictEqual(sender.recipientData, {});
    });

    it("should export RSA public key as JWK", async () => {
      const jwk = await sender.getPublicJWK();

      assert.strictEqual(jwk.kty, "RSA");
      assert.strictEqual(jwk.alg, "RS256");
      assert.ok(jwk.kid);
      assert.ok(jwk.n);
      assert.ok(jwk.e);
    });

    it("should export EC public key as JWK", async () => {
      const ecKeys = await jose.generateKeyPair("ES256");
      const sender = new TACSender({
        domain: "agent.example.com",
        privateKey: ecKeys.privateKey,
      });
      const jwk = await sender.getPublicJWK();

      assert.strictEqual(jwk.kty, "EC");
      assert.strictEqual(jwk.alg, "ES256");
      assert.strictEqual(jwk.crv, "P-256");
      assert.ok(jwk.kid);
      assert.ok(jwk.x);
      assert.ok(jwk.y);
    });

    it("should generate TAC message with proper structure", async () => {
      // Mock recipient keys
      const recipientKeys = await generateRSAKeyPair();
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      // Mock JWKS fetch
      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: "merchant.com",
          use: "enc",
          alg: "RSA-OAEP-256",
        },
      ];

      await sender.addRecipientData("merchant.com", {
        user: {
          email: { address: "test@example.com" },
          intent: "Find running shoes",
          consent: "Buy Nike Air Jordan under $200",
        },
      });

      const tacMessage = await sender.generateTACMessage();

      // Should be base64-encoded, decode to get multi-recipient message format
      const decodedMessage = Buffer.from(tacMessage, "base64").toString("utf8");
      const message = JSON.parse(decodedMessage);
      assert.strictEqual(message.version, "2025-08-27");
      assert.ok(message.recipients);
      assert.ok(Array.isArray(message.recipients));

      // Should have recipient
      assert.strictEqual(message.recipients.length, 1);
      assert.strictEqual(message.recipients[0].kid, "merchant.com");
      assert.ok(message.recipients[0].jwe); // Should contain encrypted JWE for this recipient
    });

    it("should fail to generate TAC message without recipient data", async () => {
      await assert.rejects(
        async () => await sender.generateTACMessage(),
        /No recipient data added/
      );
    });
  });

  describe("TACRecipient", () => {
    let recipientKeys;
    let recipient;

    beforeEach(async () => {
      recipientKeys = await generateRSAKeyPair();
      recipient = new TACRecipient({
        domain: "merchant.com",
        privateKey: recipientKeys.privateKey,
      });
    });

    it("should require domain and privateKey in constructor", async () => {
      assert.throws(() => new TACRecipient({}), /domain is required/);
      assert.throws(
        () => new TACRecipient({ domain: "test.com" }),
        /privateKey is required/
      );
    });

    it("should initialize with RSA keys", () => {
      assert.strictEqual(recipient.domain, "merchant.com");
      assert.ok(recipient.privateKey);
      assert.ok(recipient.publicKey);
      assert.strictEqual(recipient.privateKey.asymmetricKeyType, "rsa");
      assert.strictEqual(recipient.keyType, "RSA");
    });

    it("should initialize with EC keys", async () => {
      const ecKeys = await jose.generateKeyPair("ES256");
      const recipient = new TACRecipient({
        domain: "merchant.com",
        privateKey: ecKeys.privateKey,
      });

      assert.strictEqual(recipient.domain, "merchant.com");
      assert.strictEqual(recipient.privateKey.asymmetricKeyType, "ec");
      assert.strictEqual(recipient.publicKey.asymmetricKeyType, "ec");
      assert.strictEqual(recipient.keyType, "EC");
    });

    it("should export RSA public key as JWK", async () => {
      const jwk = await recipient.getPublicJWK();

      assert.strictEqual(jwk.kty, "RSA");
      assert.strictEqual(jwk.alg, "RS256");
      assert.ok(jwk.kid);
      assert.ok(jwk.n);
      assert.ok(jwk.e);
    });

    it("should export EC public key as JWK", async () => {
      const ecKeys = await jose.generateKeyPair("ES256");
      const recipient = new TACRecipient({
        domain: "merchant.com",
        privateKey: ecKeys.privateKey,
      });
      const jwk = await recipient.getPublicJWK();

      assert.strictEqual(jwk.kty, "EC");
      assert.strictEqual(jwk.alg, "ES256");
      assert.strictEqual(jwk.crv, "P-256");
      assert.ok(jwk.kid);
      assert.ok(jwk.x);
      assert.ok(jwk.y);
    });

    it("should process missing TAC message", async () => {
      const result = await recipient.processTACMessage(null);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.includes("Missing TAC-Protocol message"));
    });

    it("should process invalid TAC message format", async () => {
      const result = await recipient.processTACMessage("invalid-json");

      assert.strictEqual(result.valid, false);
      assert.ok(
        result.errors.some((e) =>
          e.includes("Invalid TAC-Protocol message format")
        )
      );
    });

    it("should inspect TAC message without decryption", () => {
      const mockMessage = {
        version: "2025-08-27",
        recipients: [
          { kid: "merchant.com", jwe: "encrypted_data_for_merchant" },
          { kid: "forter.com", jwe: "encrypted_data_for_forter" },
        ],
      };

      const mockMessageString = JSON.stringify(mockMessage);
      const base64MockMessage =
        Buffer.from(mockMessageString).toString("base64");
      const info = TACRecipient.inspect(base64MockMessage);

      assert.strictEqual(info.version, "2025-08-27");
      assert.deepStrictEqual(info.recipients, ["merchant.com", "forter.com"]);
    });
  });

  describe("End-to-End Integration", () => {
    let senderKeys, recipientKeys, forterKeys;
    let sender, merchant, forter;

    beforeEach(async () => {
      senderKeys = await generateRSAKeyPair();
      recipientKeys = await generateRSAKeyPair();
      forterKeys = await generateRSAKeyPair();

      sender = new TACSender({
        domain: "agent.example.com",
        privateKey: senderKeys.privateKey,
      });

      merchant = new TACRecipient({
        domain: "merchant.com",
        privateKey: recipientKeys.privateKey,
      });

      forter = new TACRecipient({
        domain: "forter.com",
        privateKey: forterKeys.privateKey,
      });
    });

    it("should work end-to-end with multiple recipients", async () => {
      // Mock JWKS fetching
      const senderJWK = await sender.getPublicJWK();
      const merchantJWK = await merchant.getPublicJWK();
      const forterJWK = await forter.getPublicJWK();

      sender.fetchJWKS = async (domain) => {
        if (domain === "merchant.com") return [merchantJWK];
        if (domain === "forter.com") return [forterJWK];
        throw new Error(`Unknown domain: ${domain}`);
      };

      merchant.fetchJWKS = async () => [senderJWK];
      forter.fetchJWKS = async () => [senderJWK];

      // Set test data for multiple recipients
      await sender.setRecipientsData({
        "merchant.com": {
          user: {
            email: { address: "customer@example.com" },
            intent: "Find reliable running shoes",
            consent: "Buy Nike Air Jordan Retro under $200",
          },
        },
        "forter.com": {
          session: {
            ipAddress: "192.168.1.1",
            userAgent: "MyAgent/1.0",
            forterToken: "ftr_xyz",
          },
        },
      });

      // Generate TAC message
      const tacMessage = await sender.generateTACMessage();

      // Both recipients should be able to process it
      const merchantResult = await merchant.processTACMessage(tacMessage);
      const forterResult = await forter.processTACMessage(tacMessage);

      // Verify merchant result
      assert.strictEqual(merchantResult.valid, true);
      assert.strictEqual(merchantResult.issuer, "agent.example.com");
      assert.ok(merchantResult.expires instanceof Date);
      assert.deepStrictEqual(merchantResult.recipients, [
        "merchant.com",
        "forter.com",
      ]);

      // Merchant should see their data
      assert.deepStrictEqual(merchantResult.data, {
        user: {
          email: { address: "customer@example.com" },
          intent: "Find reliable running shoes",
          consent: "Buy Nike Air Jordan Retro under $200",
        },
      });

      // Verify forter result
      assert.strictEqual(forterResult.valid, true);
      assert.strictEqual(forterResult.issuer, "agent.example.com");
      assert.deepStrictEqual(forterResult.recipients, [
        "merchant.com",
        "forter.com",
      ]);

      // Forter should see their data
      assert.deepStrictEqual(forterResult.data, {
        session: {
          ipAddress: "192.168.1.1",
          userAgent: "MyAgent/1.0",
          forterToken: "ftr_xyz",
        },
      });

      // Each recipient only sees their own data

      // Each recipient should only see their own data, not others'
      assert.strictEqual(
        merchantResult.data.user.email.address,
        "customer@example.com"
      );
      assert.strictEqual(forterResult.data.session.ipAddress, "192.168.1.1");

      // Verify recipients cannot see each other's data
      assert.ok(!merchantResult.data.session); // Merchant can't see Forter's session data
      assert.ok(!forterResult.data.user); // Forter can't see Merchant's user data
    });

    it("should handle non-recipient attempting to decrypt", async () => {
      const nonRecipientKeys = await generateRSAKeyPair();
      const nonRecipient = new TACRecipient({
        domain: "unauthorized.com",
        privateKey: nonRecipientKeys.privateKey,
      });

      // Setup sender with merchant as recipient
      const merchantJWK = await merchant.getPublicJWK();
      sender.fetchJWKS = async () => [merchantJWK];

      await sender.addRecipientData("merchant.com", { test: "data" });
      const tacMessage = await sender.generateTACMessage();

      // Non-recipient should fail to process
      const result = await nonRecipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some((e) => e.includes("Not a recipient")));
    });
  });

  describe("Utility Functions", () => {
    describe("JWKSCache", () => {
      let cache;

      beforeEach(() => {
        cache = new JWKSCache(1000); // 1 second timeout
      });

      it("should cache and retrieve keys", () => {
        const keys = [{ kty: "RSA", kid: "test" }];

        cache.set("test.com", keys);
        assert.deepStrictEqual(cache.get("test.com"), keys);
      });

      it("should handle cache expiry", async () => {
        const keys = [{ kty: "RSA", kid: "test" }];

        cache.set("test.com", keys);
        assert.deepStrictEqual(cache.get("test.com"), keys);

        await new Promise((resolve) => setTimeout(resolve, 1100));
        assert.strictEqual(cache.get("test.com"), null);
      });

      it("should clear cache", () => {
        const keys = [{ kty: "RSA", kid: "test" }];

        cache.set("test.com", keys);
        cache.set("example.com", keys);

        cache.clear("test.com");
        assert.strictEqual(cache.get("test.com"), null);
        assert.deepStrictEqual(cache.get("example.com"), keys);

        cache.clear();
        assert.strictEqual(cache.get("example.com"), null);
      });
    });

    describe("Key Finding Functions", () => {
      it("should find RSA encryption keys", () => {
        const keys = [
          { kty: "EC", use: "sig", alg: "ES256", kid: "ec-key" },
          {
            kty: "RSA",
            use: "enc",
            alg: "RSA-OAEP-256",
            kid: "rsa-enc",
            n: "test",
            e: "AQAB",
          },
          { kty: "RSA", use: "sig", alg: "RS256", kid: "rsa-sig" },
        ];

        const encKey = findEncryptionKey(keys);
        assert.ok(encKey);
        assert.strictEqual(encKey.kid, "rsa-enc");
        assert.strictEqual(encKey.use, "enc");
        assert.strictEqual(encKey.kty, "RSA");
      });

      it("should find RSA signing keys", () => {
        const keys = [
          { kty: "EC", use: "sig", alg: "ES256", kid: "ec-key" },
          { kty: "RSA", use: "enc", alg: "RSA-OAEP-256", kid: "rsa-enc" },
          {
            kty: "RSA",
            use: "sig",
            alg: "RS256",
            kid: "rsa-sig",
            n: "test",
            e: "AQAB",
          },
        ];

        const sigKey = findSigningKey(keys, "rsa-sig");
        assert.ok(sigKey);
        assert.strictEqual(sigKey.kid, "rsa-sig");
        assert.strictEqual(sigKey.use, "sig");
        assert.strictEqual(sigKey.kty, "RSA");
      });

      it("should return appropriate keys by type", () => {
        const keys = [
          { kty: "EC", use: "enc", alg: "ECDH-ES+A256KW", kid: "ec-enc-key" },
          { kty: "EC", use: "sig", alg: "ES256", kid: "ec-sig-key" },
          { kty: "RSA", use: "enc", alg: "RSA-OAEP-256", kid: "rsa-enc-key" },
          { kty: "RSA", use: "sig", alg: "RS256", kid: "rsa-sig-key" },
        ];

        const encKey = findEncryptionKey(keys);
        const sigKey = findSigningKey(keys);

        assert.ok(encKey);
        assert.ok(sigKey);
        assert.strictEqual(encKey.kid, "rsa-enc-key"); // Should prefer RSA encryption key
        assert.strictEqual(sigKey.kid, "rsa-sig-key"); // Should find RSA signing key
      });
    });
  });
});
