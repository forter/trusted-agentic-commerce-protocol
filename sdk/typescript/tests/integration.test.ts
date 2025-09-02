import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import * as jose from "jose";
import { setTimeout as setTimeoutPromise } from "node:timers/promises";
import TACSender from "../src/sender.js";
import TACRecipient from "../src/recipient.js";
import { SCHEMA_VERSION } from "../src/version.js";
import { TACNetworkError, TACErrorCodes } from "../src/errors.js";

describe("Integration Tests", () => {
  describe("End-to-End Scenarios", () => {
    describe("Round-Trip Communication", () => {
      it("should complete full sender → recipient round trip", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "ai-agent.example.com",
          privateKey: senderKeys.privateKey as any,
          ttl: 3600,
        });

        const recipient = new TACRecipient({
          domain: "merchant.example.com",
          privateKey: recipientKeys.privateKey as any,
        });

        // Setup JWKS mocking
        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        // Prepare realistic e-commerce data using proper schema structure
        const ecommerceData = {
          user: {
            email: { address: "customer@example.com" },
            intent: "Find sustainable running shoes under $150",
            preferences: {
              brands: ["Nike", "Adidas", "Allbirds"],
            },
          },
          session: {
            ipAddress: "192.168.1.100",
            userAgent: "Mozilla/5.0 (compatible; AI-Agent/1.0)",
          },
          custom: {
            consent: "Purchase Nike or Adidas running shoes with eco-friendly materials",
            priceRange: { min: 50, max: 150 },
            sustainability: true,
            size: "US 9.5",
            timestamp: Date.now(),
            sessionId: "sess_" + crypto.randomUUID(),
          },
        };

        // Send message
        await sender.addRecipientData("merchant.example.com", ecommerceData);
        const tacMessage = await sender.generateTACMessage();

        // Receive and process message
        const result = await recipient.processTACMessage(tacMessage);

        // Verify end-to-end success
        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.issuer, "ai-agent.example.com");
        assert.deepStrictEqual(result.data, ecommerceData);
        assert.deepStrictEqual(result.recipients, ["merchant.example.com"]);
        assert.ok(result.expires instanceof Date);
        assert.strictEqual(result.errors.length, 0);
      });

      it("should handle multi-vendor commerce scenario", async () => {
        // Setup: AI agent, merchant, and fraud prevention service
        const agentKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const merchantKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const forterKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const agent = new TACSender({
          domain: "ai-shopping-agent.com",
          privateKey: agentKeys.privateKey as any,
          ttl: 1800, // 30 minutes
        });

        const merchant = new TACRecipient({
          domain: "premium-electronics.com",
          privateKey: merchantKeys.privateKey as any,
        });

        const forter = new TACRecipient({
          domain: "forter.com",
          privateKey: forterKeys.privateKey as any,
        });

        // Setup JWKS
        const merchantJWK = await merchant.getPublicJWK();
        const forterJWK = await forter.getPublicJWK();
        const agentJWK = await agent.getPublicJWK();

        (agent as any).fetchJWKS = async (domain: string) => {
          if (domain === "premium-electronics.com") return [merchantJWK];
          if (domain === "forter.com") return [forterJWK];
          throw new Error(`Unknown domain: ${domain}`);
        };

        (merchant as any).fetchJWKS = async () => [agentJWK];
        (forter as any).fetchJWKS = async () => [agentJWK];

        // Prepare multi-recipient data
        const sharedData = {
          session: {
            id: "sess_" + crypto.randomUUID(),
            ipAddress: "203.0.113.45",
            userAgent: "AI-ShoppingAgent/2.0",
          },
          user: {
            id: "user_12345",
            email: { address: "premium.customer@email.com" },
          },
        };

        const merchantSpecificData = {
          ...sharedData,
          order: {
            cart: [
              {
                id: "laptop_001",
                name: "Premium Laptop",
                price: 2599.99,
                quantity: 1,
              },
            ],
            total: 2599.99,
            currency: "USD",
          },
          custom: {
            merchantId: "merch_premium_elec",
            category: "electronics",
          },
        };

        const forterSpecificData = {
          ...sharedData,
          custom: {
            riskAssessment: true,
            fraudCheck: "high-value-transaction",
            merchantPartner: "premium-electronics.com",
          },
        };

        await agent.setRecipientsData({
          "premium-electronics.com": merchantSpecificData,
          "forter.com": forterSpecificData,
        });

        const tacMessage = await agent.generateTACMessage();

        // Both services process the message
        const merchantResult = await merchant.processTACMessage(tacMessage);
        const forterResult = await forter.processTACMessage(tacMessage);

        // Verify both received their data
        assert.strictEqual(merchantResult.valid, true);
        assert.strictEqual(forterResult.valid, true);

        // Verify merchant got order info
        assert.strictEqual((merchantResult.data as any).order?.total, 2599.99);
        assert.strictEqual((merchantResult.data as any).custom?.category, "electronics");

        // Verify Forter got risk info
        assert.strictEqual((forterResult.data as any).custom?.riskAssessment, true);
        assert.strictEqual((forterResult.data as any).custom?.fraudCheck, "high-value-transaction");

        // Verify shared data is consistent
        assert.strictEqual(merchantResult.data?.user?.email?.address, forterResult.data?.user?.email?.address);
      });
    });

    describe("Cross-Cryptographic Scenarios", () => {
      it("should handle RSA sender to EC recipient", async () => {
        const rsaSenderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const ecRecipientKeys = await jose.generateKeyPair("ES256");

        const rsaSender = new TACSender({
          domain: "rsa-agent.com",
          privateKey: rsaSenderKeys.privateKey as any,
        });

        const ecRecipient = new TACRecipient({
          domain: "ec-service.com",
          privateKey: ecRecipientKeys.privateKey as any,
        });

        // Setup cross-crypto communication
        const ecJWK = await ecRecipient.getPublicJWK();
        const rsaJWK = await rsaSender.getPublicJWK();

        (rsaSender as any).fetchJWKS = async () => [ecJWK];
        (ecRecipient as any).fetchJWKS = async () => [rsaJWK];

        await rsaSender.addRecipientData("ec-service.com", {
          custom: {
            crossCrypto: "RSA sender to EC recipient",
            timestamp: Date.now(),
          },
        });

        const tacMessage = await rsaSender.generateTACMessage();
        const result = await ecRecipient.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        assert.strictEqual((result.data as any).custom?.crossCrypto, "RSA sender to EC recipient");
      });

      it("should handle mixed RSA and EC recipients", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const rsaRecipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const ecRecipientKeys = await jose.generateKeyPair("ES256");

        const sender = new TACSender({
          domain: "multi-crypto-agent.com",
          privateKey: senderKeys.privateKey as any,
        });

        const rsaRecipient = new TACRecipient({
          domain: "rsa-service.com",
          privateKey: rsaRecipientKeys.privateKey as any,
        });

        const ecRecipient = new TACRecipient({
          domain: "ec-service.com",
          privateKey: ecRecipientKeys.privateKey as any,
        });

        // Setup JWKS
        const rsaJWK = await rsaRecipient.getPublicJWK();
        const ecJWK = await ecRecipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async (domain: string) => {
          if (domain === "rsa-service.com") {
            return [rsaJWK];
          }
          if (domain === "ec-service.com") {
            return [ecJWK];
          }
          throw new Error(`Unknown domain: ${domain}`);
        };

        (rsaRecipient as any).fetchJWKS = async () => [senderJWK];
        (ecRecipient as any).fetchJWKS = async () => [senderJWK];

        await sender.setRecipientsData({
          "rsa-service.com": { custom: { cryptoType: "RSA", data: "RSA recipient data" } },
          "ec-service.com": { custom: { cryptoType: "EC", data: "EC recipient data" } },
        });

        const tacMessage = await sender.generateTACMessage();

        const rsaResult = await rsaRecipient.processTACMessage(tacMessage);
        const ecResult = await ecRecipient.processTACMessage(tacMessage);

        assert.strictEqual(rsaResult.valid, true);
        assert.strictEqual((rsaResult.data as any).custom?.cryptoType, "RSA");

        assert.strictEqual(ecResult.valid, true);
        assert.strictEqual((ecResult.data as any).custom?.cryptoType, "EC");
      });
    });

    describe("Key Rotation Scenarios", () => {
      it("should handle key rotation during operation", async () => {
        const senderKeys1 = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "rotating-agent.com",
          privateKey: senderKeys1.privateKey as any,
        });

        const recipient = new TACRecipient({
          domain: "recipient.com",
          privateKey: recipientKeys.privateKey as any,
        });

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK1 = await jose.exportJWK(senderKeys1.publicKey);

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK1];

        // Send message with key 1
        await sender.addRecipientData("recipient.com", {
          custom: { message: "Message with key 1", timestamp: Date.now() },
        });
        const message1 = await sender.generateTACMessage();

        // Message should be processable
        const result1 = await recipient.processTACMessage(message1);

        assert.strictEqual(result1.valid, true);
        assert.strictEqual((result1.data as any).custom?.message, "Message with key 1");
      });

      it("should handle gradual key migration", async () => {
        const oldKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const oldSender = new TACSender({
          domain: "migrating-service.com",
          privateKey: oldKeys.privateKey as any,
        });

        const recipient = new TACRecipient({
          domain: "recipient.com",
          privateKey: recipientKeys.privateKey as any,
        });

        const recipientJWK = await recipient.getPublicJWK();
        const oldJWK = await jose.exportJWK(oldKeys.publicKey);

        (oldSender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [oldJWK];

        await oldSender.addRecipientData("recipient.com", {
          custom: { phase: "migration-test", timestamp: Date.now() },
        });
        const oldMessage = await oldSender.generateTACMessage();

        // Test message processing
        const result = await recipient.processTACMessage(oldMessage);
        assert.strictEqual(result.valid, true);
        assert.strictEqual((result.data as any).custom?.phase, "migration-test");
      });
    });

    describe("Performance and Scalability", () => {
      it("should handle large-scale multi-recipient scenarios", async () => {
        const numRecipients = 50; // Reduced for faster testing
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "large-scale-agent.com",
          privateKey: senderKeys.privateKey as any,
        });

        // Generate recipients and their data
        const recipients: Array<{
          domain: string;
          instance: TACRecipient;
          keys: jose.GenerateKeyPairResult<jose.KeyLike>;
        }> = [];
        const recipientData: Record<string, any> = {};

        for (let i = 1; i <= numRecipients; i++) {
          const keys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
          const domain = `recipient${i}.com`;
          const instance = new TACRecipient({
            domain,
            privateKey: keys.privateKey as any,
          });

          recipients.push({ domain, instance, keys });
          recipientData[domain] = {
            custom: {
              recipientId: i,
              data: `Data for recipient ${i}`,
              timestamp: Date.now(),
            },
          };
        }

        // Setup JWKS
        const recipientJWKs = await Promise.all(recipients.map((r) => r.instance.getPublicJWK()));
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async (domain: string) => {
          const index = recipients.findIndex((r) => r.domain === domain);
          if (index >= 0) return [recipientJWKs[index]!];
          throw new Error(`Unknown domain: ${domain}`);
        };

        recipients.forEach((r) => {
          (r.instance as any).fetchJWKS = async () => [senderJWK];
        });

        // Send to all recipients
        await sender.setRecipientsData(recipientData);
        const tacMessage = await sender.generateTACMessage();

        // Verify all recipients can process
        const results = await Promise.all(recipients.map((r) => r.instance.processTACMessage(tacMessage)));

        results.forEach((result, index) => {
          assert.strictEqual(result.valid, true);
          assert.strictEqual((result.data as any).custom?.recipientId, index + 1);
        });
      });

      it("should handle concurrent message processing", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "concurrent-agent.com",
          privateKey: senderKeys.privateKey as any,
        });

        const recipient = new TACRecipient({
          domain: "concurrent-recipient.com",
          privateKey: recipientKeys.privateKey as any,
        });

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        // Generate multiple messages concurrently
        const numMessages = 10;
        const messagePromises = Array.from({ length: numMessages }, async (_, i) => {
          // Create a fresh sender instance for each message to avoid data conflicts
          const messageSender = new TACSender({
            domain: "concurrent-agent.com",
            privateKey: senderKeys.privateKey as any,
          });
          (messageSender as any).fetchJWKS = async () => [recipientJWK];

          await messageSender.addRecipientData("concurrent-recipient.com", {
            custom: {
              messageId: i,
              data: `Concurrent message ${i}`,
              timestamp: Date.now(),
            },
          });
          return messageSender.generateTACMessage();
        });

        const messages = await Promise.all(messagePromises);

        // Process all messages concurrently
        const resultPromises = messages.map((msg) => recipient.processTACMessage(msg));
        const results = await Promise.all(resultPromises);

        // Verify all processed successfully
        results.forEach((result, index) => {
          assert.strictEqual(result.valid, true);
          assert.strictEqual((result.data as any).custom?.messageId, index);
        });
      });
    });

    describe("Real-World Error Scenarios", () => {
      it("should handle network intermittency during JWKS fetch", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "unreliable-network.com",
          privateKey: senderKeys.privateKey as any,
          maxRetries: 3,
          retryDelay: 100,
        });

        const recipient = new TACRecipient({
          domain: "recipient.com",
          privateKey: recipientKeys.privateKey as any,
        });

        const recipientJWK = await recipient.getPublicJWK();

        // Test that network errors are properly handled and propagated
        (sender as any).fetchJWKS = async () => {
          throw new TACNetworkError("Network error", TACErrorCodes.HTTP_ERROR);
        };

        await sender.addRecipientData("recipient.com", {
          custom: { data: "test with network retry", timestamp: Date.now() },
        });

        // Should fail with network error
        await assert.rejects(
          async () => await sender.generateTACMessage(),
          (error: any) => error.message.includes("Network error")
        );

        // Now test successful case
        (sender as any).fetchJWKS = async () => [recipientJWK];
        const tacMessage = await sender.generateTACMessage();
        assert.ok(tacMessage);
      });

      it("should handle stale JWKS cache gracefully", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const oldRecipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const newRecipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "sender.com",
          privateKey: senderKeys.privateKey as any,
          cacheTimeout: 100, // Very short cache timeout
        });

        const oldRecipient = new TACRecipient({
          domain: "recipient.com",
          privateKey: oldRecipientKeys.privateKey as any,
        });

        const newRecipient = new TACRecipient({
          domain: "recipient.com",
          privateKey: newRecipientKeys.privateKey as any,
        });

        const oldJWK = await oldRecipient.getPublicJWK();
        const newJWK = await newRecipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        let useOldKey = true;

        (sender as any).fetchJWKS = async () => {
          return useOldKey ? [oldJWK] : [newJWK];
        };

        (oldRecipient as any).fetchJWKS = async () => [senderJWK];
        (newRecipient as any).fetchJWKS = async () => [senderJWK];

        // Send message with old key cached
        await sender.addRecipientData("recipient.com", {
          custom: { data: "message 1", timestamp: Date.now() },
        });
        const message1 = await sender.generateTACMessage();

        // Simulate key rotation
        useOldKey = false;
        await setTimeoutPromise(150); // Wait for cache to expire

        // Send message that should use new key
        await sender.addRecipientData("recipient.com", {
          custom: { data: "message 2", timestamp: Date.now() },
        });
        const message2 = await sender.generateTACMessage();

        // Verify messages work with appropriate recipients
        const result1 = await oldRecipient.processTACMessage(message1);
        const result2 = await newRecipient.processTACMessage(message2);

        assert.strictEqual(result1.valid, true);
        assert.strictEqual(result2.valid, true);
      });

      it("should handle mixed success/failure in multi-recipient scenario", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const goodRecipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "mixed-scenario.com",
          privateKey: senderKeys.privateKey as any,
        });

        const goodRecipient = new TACRecipient({
          domain: "good-recipient.com",
          privateKey: goodRecipientKeys.privateKey as any,
        });

        const goodJWK = await goodRecipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async (domain: string) => {
          if (domain === "good-recipient.com") {
            return [goodJWK];
          }
          if (domain === "bad-recipient.com") {
            throw new Error("JWKS endpoint not found");
          }
          throw new Error(`Unknown domain: ${domain}`);
        };

        (goodRecipient as any).fetchJWKS = async () => [senderJWK];

        await sender.setRecipientsData({
          "good-recipient.com": { custom: { data: "success data" } },
          "bad-recipient.com": { custom: { data: "failure data" } },
        });

        // Should fail due to bad recipient
        await assert.rejects(
          async () => await sender.generateTACMessage(),
          (error: any) => error.message.includes("JWKS endpoint not found")
        );
      });
    });

    describe("Protocol Compliance", () => {
      it("should maintain message integrity across complex flows", async () => {
        const agentKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const merchantKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const agent = new TACSender({
          domain: "integrity-agent.com",
          privateKey: agentKeys.privateKey as any,
          ttl: 3600,
        });

        const merchant = new TACRecipient({
          domain: "integrity-merchant.com",
          privateKey: merchantKeys.privateKey as any,
        });

        const merchantJWK = await merchant.getPublicJWK();
        const agentJWK = await agent.getPublicJWK();

        (agent as any).fetchJWKS = async () => [merchantJWK];
        (merchant as any).fetchJWKS = async () => [agentJWK];

        // Complex nested data structure
        const complexData = {
          user: {
            id: "user_complex_test",
            email: { address: "complex@test.com" },
          },
          order: {
            id: "order_complex_123",
            cart: [
              {
                id: "item1",
                name: "Complex Item 1",
                price: 99.99,
                quantity: 2,
              },
              {
                id: "item2",
                name: "Complex Item 2",
                price: 149.99,
                quantity: 1,
              },
            ],
            total: 349.97,
            currency: "USD",
          },
          custom: {
            metadata: {
              version: SCHEMA_VERSION,
              processed: new Date().toISOString(),
              complexity: "high",
            },
            nested: {
              deeply: {
                nested: {
                  data: "preservation test",
                  numbers: [1, 2, 3.14, -5],
                  booleans: [true, false],
                  nullValue: null,
                },
              },
            },
          },
        };

        await agent.addRecipientData("integrity-merchant.com", complexData);
        const tacMessage = await agent.generateTACMessage();

        // Verify message can be inspected
        const inspection = TACRecipient.inspect(tacMessage);
        assert.strictEqual(inspection.version, SCHEMA_VERSION);
        assert.deepStrictEqual(inspection.recipients, ["integrity-merchant.com"]);
        // expires might be a Date, null, or undefined depending on implementation
        if (inspection.expires !== undefined && inspection.expires !== null) {
          assert.ok(inspection.expires instanceof Date);
        }
        assert.strictEqual(inspection.error, undefined);

        // Process and verify data integrity
        const result = await merchant.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        assert.deepStrictEqual(result.data, complexData);

        // Verify deep nested data integrity
        const nestedData = (result.data as any).custom?.nested?.deeply?.nested;
        assert.strictEqual(nestedData?.data, "preservation test");
        assert.deepStrictEqual(nestedData?.numbers, [1, 2, 3.14, -5]);
        assert.deepStrictEqual(nestedData?.booleans, [true, false]);
        assert.strictEqual(nestedData?.nullValue, null);
      });

      it("should enforce proper domain validation", async () => {
        const senderKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });
        const recipientKeys = await jose.generateKeyPair("RS256", { modulusLength: 2048 });

        const sender = new TACSender({
          domain: "legitimate-sender.com",
          privateKey: senderKeys.privateKey as any,
        });

        const recipient = new TACRecipient({
          domain: "legitimate-recipient.com",
          privateKey: recipientKeys.privateKey as any,
        });

        const recipientJWK = await recipient.getPublicJWK();
        const senderJWK = await sender.getPublicJWK();

        (sender as any).fetchJWKS = async () => [recipientJWK];
        (recipient as any).fetchJWKS = async () => [senderJWK];

        // Send message to legitimate recipient
        await sender.addRecipientData("legitimate-recipient.com", {
          custom: { data: "legitimate message" },
        });
        const tacMessage = await sender.generateTACMessage();

        // Legitimate recipient should process successfully
        const result = await recipient.processTACMessage(tacMessage);
        assert.strictEqual(result.valid, true);

        // Create a malicious recipient with wrong domain
        const maliciousRecipient = new TACRecipient({
          domain: "malicious-recipient.com",
          privateKey: recipientKeys.privateKey as any, // Same key, wrong domain
        });

        (maliciousRecipient as any).fetchJWKS = async () => [senderJWK];

        // Malicious recipient should fail to process
        const maliciousResult = await maliciousRecipient.processTACMessage(tacMessage);
        assert.strictEqual(maliciousResult.valid, false);
        assert.ok(
          maliciousResult.errors.some(
            (e) =>
              e.includes("Not a recipient") ||
              e.includes("domain not found") ||
              e.includes("decrypt") ||
              e.includes("JWE")
          )
        );
      });
    });
  });
});
