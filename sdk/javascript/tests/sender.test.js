import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as jose from 'jose';
import TACSender from '../src/sender.js';
import { SCHEMA_VERSION } from '../src/version.js';

// Helper function to decrypt and verify JWS+JWE messages
async function decryptAndVerifyMessage(jwe, recipientPrivateKey, senderPublicKey) {
  // Step 1: Decrypt the JWE to get the signed JWT
  const { plaintext } = await jose.compactDecrypt(jwe, recipientPrivateKey);
  const signedJWT = new TextDecoder().decode(plaintext);

  // Step 2: Verify the JWT signature
  const { payload } = await jose.jwtVerify(signedJWT, senderPublicKey);

  return { payload };
}

describe('TACSender - Message Generation', () => {
  let sender;
  let senderKeys;

  beforeEach(async () => {
    senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
    sender = new TACSender({
      domain: 'agent.example.com',
      privateKey: senderKeys.privateKey,
      ttl: 3600
    });
  });

  describe('JWT Creation', () => {
    it('should create JWT with required claims', async () => {
      // Mock recipient
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('recipient.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();

      // Decode and inspect the JWT
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Get the recipient JWE and decode its payload to check JWT claims
      const recipientJWE = message.recipients[0].jwe;

      // Decrypt and verify the JWS+JWE message
      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const { payload } = await decryptAndVerifyMessage(recipientJWE, recipientKeys.privateKey, senderPublicKey);

      // Verify required claims
      assert.ok(payload.iss, 'Should have iss claim');
      assert.ok(payload.exp, 'Should have exp claim');
      assert.ok(payload.iat, 'Should have iat claim');
      assert.ok(payload.aud, 'Should have aud claim');

      assert.strictEqual(payload.iss, 'agent.example.com');
      assert.strictEqual(payload.aud, 'recipient.com');
    });

    it('should set correct expiration time based on TTL', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      const beforeGeneration = Math.floor(Date.now() / 1000);
      await sender.addRecipientData('recipient.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();
      const afterGeneration = Math.floor(Date.now() / 1000);

      // Decode and check expiration
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);
      const recipientJWE = message.recipients[0].jwe;
      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const decrypted = await decryptAndVerifyMessage(recipientJWE, recipientKeys.privateKey, senderPublicKey);

      const expectedExpMin = beforeGeneration + 3600;
      const expectedExpMax = afterGeneration + 3600;

      assert.ok(decrypted.payload.exp >= expectedExpMin);
      assert.ok(decrypted.payload.exp <= expectedExpMax);
    });

    it('should use second-precision timestamps', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('recipient.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);
      const recipientJWE = message.recipients[0].jwe;
      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const decrypted = await decryptAndVerifyMessage(recipientJWE, recipientKeys.privateKey, senderPublicKey);

      // Should be integers (second precision)
      assert.strictEqual(decrypted.payload.iat % 1, 0);
      assert.strictEqual(decrypted.payload.exp % 1, 0);
    });

    it('should match audience claim to recipient domain', async () => {
      const recipient1Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipient2Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const recipient1JWK = await jose.exportJWK(recipient1Keys.publicKey);
      const recipient2JWK = await jose.exportJWK(recipient2Keys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'recipient1.com') {
          return [
            {
              ...recipient1JWK,
              kid: 'recipient1.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'recipient2.com') {
          return [
            {
              ...recipient2JWK,
              kid: 'recipient2.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'recipient1.com': { data: 'for recipient 1' },
        'recipient2.com': { data: 'for recipient 2' }
      });

      const tacMessage = await sender.generateTACMessage();
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Check each recipient's JWT audience
      for (const recipient of message.recipients) {
        if (recipient.kid === 'recipient1.com') {
          const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
          const decrypted = await decryptAndVerifyMessage(recipient.jwe, recipient1Keys.privateKey, senderPublicKey);
          assert.strictEqual(decrypted.payload.aud, 'recipient1.com');
        } else if (recipient.kid === 'recipient2.com') {
          const senderPublicKey2 = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
          const decrypted = await decryptAndVerifyMessage(recipient.jwe, recipient2Keys.privateKey, senderPublicKey2);
          assert.strictEqual(decrypted.payload.aud, 'recipient2.com');
        }
      }
    });

    it('should include various data structures in payload', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      const complexData = {
        user: {
          email: { address: 'test@example.com' },
          intent: 'Buy running shoes',
          preferences: ['Nike', 'Adidas'],
          profile: {
            age: 30,
            location: 'US',
            active: true
          }
        },
        session: {
          ipAddress: '192.168.1.1',
          timestamp: Date.now(),
          metadata: null
        },
        numbers: [1, 2, 3.14, -5],
        flags: { premium: true, verified: false }
      };

      await sender.addRecipientData('recipient.com', complexData);
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);
      const recipientJWE = message.recipients[0].jwe;
      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const decrypted = await decryptAndVerifyMessage(recipientJWE, recipientKeys.privateKey, senderPublicKey);

      assert.deepStrictEqual(decrypted.payload.data, complexData);
    });
  });

  describe('Multi-Recipient Encryption', () => {
    it('should handle single recipient', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'single.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('single.com', { message: 'Hello single recipient' });
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      assert.strictEqual(message.recipients.length, 1);
      assert.strictEqual(message.recipients[0].kid, 'single.com');
      assert.ok(message.recipients[0].jwe);
    });

    it('should handle multiple recipients (2 recipients)', async () => {
      const recipient1Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipient2Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const recipient1JWK = await jose.exportJWK(recipient1Keys.publicKey);
      const recipient2JWK = await jose.exportJWK(recipient2Keys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'recipient1.com') {
          return [
            {
              ...recipient1JWK,
              kid: 'recipient1.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'recipient2.com') {
          return [
            {
              ...recipient2JWK,
              kid: 'recipient2.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'recipient1.com': { data: 'for recipient 1' },
        'recipient2.com': { data: 'for recipient 2' }
      });

      const tacMessage = await sender.generateTACMessage();
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      assert.strictEqual(message.recipients.length, 2);

      const kids = message.recipients.map(r => r.kid);
      assert.ok(kids.includes('recipient1.com'));
      assert.ok(kids.includes('recipient2.com'));
    });

    it('should handle many recipients (10+ recipients)', async () => {
      const numRecipients = 12;
      const recipientData = {};
      const recipientKeys = {};

      // Generate keys for all recipients
      for (let i = 1; i <= numRecipients; i++) {
        const domain = `recipient${i}.com`;
        recipientKeys[domain] = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        recipientData[domain] = { message: `Data for recipient ${i}` };
      }

      sender.fetchJWKS = async domain => {
        if (recipientKeys[domain]) {
          const jwk = await jose.exportJWK(recipientKeys[domain].publicKey);
          return [
            {
              ...jwk,
              kid: domain,
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        }
        throw new Error(`Unknown domain: ${domain}`);
      };

      await sender.setRecipientsData(recipientData);
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      assert.strictEqual(message.recipients.length, numRecipients);

      // Verify all recipients are present
      const kids = message.recipients.map(r => r.kid);
      for (let i = 1; i <= numRecipients; i++) {
        assert.ok(kids.includes(`recipient${i}.com`));
      }
    });

    it('should handle mix of RSA and EC recipients', async () => {
      const rsaKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const ecKeys = await jose.generateKeyPair('ES256');

      const rsaJWK = await jose.exportJWK(rsaKeys.publicKey);
      const ecJWK = await jose.exportJWK(ecKeys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'rsa-recipient.com') {
          return [
            {
              ...rsaJWK,
              kid: 'rsa-recipient.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'ec-recipient.com') {
          return [
            {
              ...ecJWK,
              kid: 'ec-recipient.com',
              use: 'enc',
              alg: 'ECDH-ES+A256KW'
            }
          ];
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'rsa-recipient.com': { data: 'for RSA recipient' },
        'ec-recipient.com': { data: 'for EC recipient' }
      });

      const tacMessage = await sender.generateTACMessage();
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      assert.strictEqual(message.recipients.length, 2);

      // Both recipients should be able to decrypt their messages
      for (const recipient of message.recipients) {
        if (recipient.kid === 'rsa-recipient.com') {
          const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
          const decrypted = await decryptAndVerifyMessage(recipient.jwe, rsaKeys.privateKey, senderPublicKey);
          assert.deepStrictEqual(decrypted.payload.data, { data: 'for RSA recipient' });
        } else if (recipient.kid === 'ec-recipient.com') {
          const senderPublicKey2 = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
          const decrypted = await decryptAndVerifyMessage(recipient.jwe, ecKeys.privateKey, senderPublicKey2);
          assert.deepStrictEqual(decrypted.payload.data, { data: 'for EC recipient' });
        }
      }
    });

    it('should ensure recipient data isolation', async () => {
      const recipient1Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipient2Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const recipient1JWK = await jose.exportJWK(recipient1Keys.publicKey);
      const recipient2JWK = await jose.exportJWK(recipient2Keys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'recipient1.com') {
          return [
            {
              ...recipient1JWK,
              kid: 'recipient1.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'recipient2.com') {
          return [
            {
              ...recipient2JWK,
              kid: 'recipient2.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'recipient1.com': {
          secret: 'recipient1-secret-data',
          shared: 'common-data'
        },
        'recipient2.com': {
          secret: 'recipient2-secret-data',
          shared: 'common-data'
        }
      });

      const tacMessage = await sender.generateTACMessage();
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Each recipient should only see their own data
      for (const recipient of message.recipients) {
        if (recipient.kid === 'recipient1.com') {
          const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
          const decrypted = await decryptAndVerifyMessage(recipient.jwe, recipient1Keys.privateKey, senderPublicKey);
          assert.strictEqual(decrypted.payload.data.secret, 'recipient1-secret-data');
          assert.strictEqual(decrypted.payload.data.shared, 'common-data');

          // Should not be able to decrypt with recipient2's key
          await assert.rejects(async () => {
            const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
            await decryptAndVerifyMessage(recipient.jwe, recipient2Keys.privateKey, senderPublicKey);
          }, /JWEDecryptionFailed|decryption operation failed/);
        } else if (recipient.kid === 'recipient2.com') {
          const senderPublicKey2 = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
          const decrypted = await decryptAndVerifyMessage(recipient.jwe, recipient2Keys.privateKey, senderPublicKey2);
          assert.strictEqual(decrypted.payload.data.secret, 'recipient2-secret-data');
          assert.strictEqual(decrypted.payload.data.shared, 'common-data');

          // Should not be able to decrypt with recipient1's key
          await assert.rejects(async () => {
            const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
            await decryptAndVerifyMessage(recipient.jwe, recipient1Keys.privateKey, senderPublicKey);
          }, /JWEDecryptionFailed|decryption operation failed/);
        }
      }
    });

    it('should handle when JWKS fetch fails for one recipient', async () => {
      const validRecipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const validRecipientJWK = await jose.exportJWK(validRecipientKeys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'valid.com') {
          return [
            {
              ...validRecipientJWK,
              kid: 'valid.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'invalid.com') {
          throw new Error('JWKS fetch failed');
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'valid.com': { data: 'valid recipient data' },
        'invalid.com': { data: 'invalid recipient data' }
      });

      // Should fail when JWKS fetch fails for any recipient
      await assert.rejects(async () => await sender.generateTACMessage(), /JWKS fetch failed/);
    });

    it('should handle duplicate recipient domains', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'duplicate.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      // Add data for same domain multiple times (should overwrite)
      await sender.addRecipientData('duplicate.com', { data: 'first' });
      await sender.addRecipientData('duplicate.com', { data: 'second' });

      const tacMessage = await sender.generateTACMessage();
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Should only have one recipient
      assert.strictEqual(message.recipients.length, 1);
      assert.strictEqual(message.recipients[0].kid, 'duplicate.com');

      // Should contain the last data set
      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const decrypted = await decryptAndVerifyMessage(
        message.recipients[0].jwe,
        recipientKeys.privateKey,
        senderPublicKey
      );
      assert.deepStrictEqual(decrypted.payload.data, { data: 'second' });
    });
  });

  describe('Message Format', () => {
    it('should use proper base64 encoding', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('recipient.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();

      // Should be valid base64
      assert.ok(/^[A-Za-z0-9+/]*={0,2}$/.test(tacMessage));

      // Should be decodable
      const decoded = Buffer.from(tacMessage, 'base64').toString('utf8');
      assert.ok(decoded.length > 0);

      // Should be valid JSON
      const parsed = JSON.parse(decoded);
      assert.ok(typeof parsed === 'object');
    });

    it('should follow correct JSON structure', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('recipient.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Verify structure
      assert.ok(message.version);
      assert.ok(Array.isArray(message.recipients));
      assert.strictEqual(typeof message.version, 'string');
    });

    it('should include correct schema version', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('recipient.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      assert.strictEqual(message.version, SCHEMA_VERSION);
    });

    it('should include kid and jwe fields for each recipient', async () => {
      const recipient1Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipient2Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const recipient1JWK = await jose.exportJWK(recipient1Keys.publicKey);
      const recipient2JWK = await jose.exportJWK(recipient2Keys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'recipient1.com') {
          return [
            {
              ...recipient1JWK,
              kid: 'recipient1.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'recipient2.com') {
          return [
            {
              ...recipient2JWK,
              kid: 'recipient2.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'recipient1.com': { data: 'for recipient 1' },
        'recipient2.com': { data: 'for recipient 2' }
      });

      const tacMessage = await sender.generateTACMessage();
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Verify each recipient has required fields
      message.recipients.forEach(recipient => {
        assert.ok(recipient.kid);
        assert.ok(recipient.jwe);
        assert.strictEqual(typeof recipient.kid, 'string');
        assert.strictEqual(typeof recipient.jwe, 'string');
      });
    });
  });

  describe('Large Data Handling', () => {
    it('should handle large payloads (1MB)', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      // Create ~1MB of data
      const largeString = 'x'.repeat(1024 * 1024);
      const largeData = {
        largeField: largeString,
        metadata: { size: largeString.length }
      };

      await sender.addRecipientData('recipient.com', largeData);
      const tacMessage = await sender.generateTACMessage();

      // Should successfully create and be decodable
      assert.ok(tacMessage.length > 0);

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Should be able to decrypt
      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const decrypted = await decryptAndVerifyMessage(
        message.recipients[0].jwe,
        recipientKeys.privateKey,
        senderPublicKey
      );
      assert.strictEqual(decrypted.payload.data.largeField.length, 1024 * 1024);
    });

    it('should handle complex nested data structures', async () => {
      const recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...recipientJWK,
          kid: 'recipient.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      const complexData = {
        level1: {
          level2: {
            level3: {
              level4: {
                array: [{ nested: { data: 'deep' } }, { more: { complex: ['arrays', 'of', 'data'] } }],
                boolean: true,
                number: 3.14159,
                nullValue: null
              }
            }
          }
        },
        topLevelArray: Array.from({ length: 100 }, (_, i) => ({
          id: i,
          value: `item-${i}`,
          metadata: { index: i, even: i % 2 === 0 }
        }))
      };

      await sender.addRecipientData('recipient.com', complexData);
      const tacMessage = await sender.generateTACMessage();

      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      const senderPublicKey = await jose.importJWK(await jose.exportJWK(senderKeys.publicKey));
      const decrypted = await decryptAndVerifyMessage(
        message.recipients[0].jwe,
        recipientKeys.privateKey,
        senderPublicKey
      );
      assert.deepStrictEqual(decrypted.payload.data, complexData);
    });
  });

  describe('Error Conditions', () => {
    it('should fail when no recipient data is added', async () => {
      await assert.rejects(async () => await sender.generateTACMessage(), /No recipient data added/);
    });

    it('should fail when recipient data is cleared', async () => {
      await sender.addRecipientData('test.com', { data: 'test' });
      sender.clearRecipientData();

      await assert.rejects(async () => await sender.generateTACMessage(), /No recipient data added/);
    });

    it('should fail when no encryption key found for recipient', async () => {
      sender.fetchJWKS = async () => [
        // Only signing key, no encryption key
        {
          kty: 'RSA',
          kid: 'test-key',
          use: 'sig',
          alg: 'RS256',
          n: 'test',
          e: 'AQAB'
        }
      ];

      await sender.addRecipientData('recipient.com', { test: 'data' });

      await assert.rejects(async () => await sender.generateTACMessage(), /No suitable encryption key found/);
    });

    it('should fail when JWKS endpoint is unreachable', async () => {
      sender.fetchJWKS = async () => {
        throw new Error('Network error');
      };

      await sender.addRecipientData('unreachable.com', { test: 'data' });

      await assert.rejects(async () => await sender.generateTACMessage(), /Network error/);
    });
  });
});
