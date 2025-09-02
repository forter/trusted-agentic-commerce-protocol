import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as jose from 'jose';
import TACSender from '../src/sender.js';
import TACRecipient from '../src/recipient.js';
import { SCHEMA_VERSION } from '../src/version.js';

describe('TACRecipient - Message Processing', () => {
  let recipient;
  let recipientKeys;
  let sender;
  let senderKeys;

  beforeEach(async () => {
    recipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
    senderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

    recipient = new TACRecipient({
      domain: 'recipient.com',
      privateKey: recipientKeys.privateKey
    });

    sender = new TACSender({
      domain: 'sender.com',
      privateKey: senderKeys.privateKey,
      ttl: 3600
    });
  });

  describe('Message Validation', () => {
    it('should process valid message successfully', async () => {
      // Setup mock JWKS
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => [senderJWK];

      // Generate valid message
      await sender.addRecipientData('recipient.com', {
        user: { email: { address: 'test@example.com' } }
      });

      const tacMessage = await sender.generateTACMessage();
      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.issuer, 'sender.com');
      assert.ok(result.expires instanceof Date);
      assert.deepStrictEqual(result.recipients, ['recipient.com']);
      assert.deepStrictEqual(result.data, {
        user: { email: { address: 'test@example.com' } }
      });
      assert.strictEqual(result.errors.length, 0);
    });

    it('should handle missing TAC message (null)', async () => {
      const result = await recipient.processTACMessage(null);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.includes('Missing TAC-Protocol message'));
      assert.strictEqual(result.issuer, null);
      assert.strictEqual(result.data, null);
    });

    it('should handle missing TAC message (undefined)', async () => {
      const result = await recipient.processTACMessage(undefined);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.includes('Missing TAC-Protocol message'));
    });

    it('should handle empty string message', async () => {
      const result = await recipient.processTACMessage('');

      assert.strictEqual(result.valid, false);
      assert.ok(
        result.errors.some(
          e => e.includes('Invalid TAC-Protocol message format') || e.includes('Missing TAC-Protocol message')
        )
      );
    });

    it('should handle invalid base64 encoding', async () => {
      const result = await recipient.processTACMessage('invalid-base64!');

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Invalid TAC-Protocol message format')));
    });

    it('should handle malformed JSON', async () => {
      const invalidJson = '{ invalid json }';
      const base64Invalid = Buffer.from(invalidJson).toString('base64');

      const result = await recipient.processTACMessage(base64Invalid);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Invalid TAC-Protocol message format')));
    });

    it('should handle missing recipients array', async () => {
      const messageWithoutRecipients = {
        version: SCHEMA_VERSION
        // missing recipients
      };
      const base64Message = Buffer.from(JSON.stringify(messageWithoutRecipients)).toString('base64');

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(
        result.errors.some(e => e.includes('Invalid message structure') || e.includes('Invalid message format'))
      );
    });

    it('should handle non-array recipients field', async () => {
      const messageWithInvalidRecipients = {
        version: SCHEMA_VERSION,
        recipients: 'not-an-array'
      };
      const base64Message = Buffer.from(JSON.stringify(messageWithInvalidRecipients)).toString('base64');

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(
        result.errors.some(e => e.includes('Invalid message structure') || e.includes('Invalid message format'))
      );
    });

    it('should handle when not a recipient', async () => {
      const senderJWK = await sender.getPublicJWK();
      recipient.fetchJWKS = async () => [senderJWK];

      // Create message for different recipient
      const otherRecipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const otherRecipientJWK = await jose.exportJWK(otherRecipientKeys.publicKey);

      sender.fetchJWKS = async () => [
        {
          ...otherRecipientJWK,
          kid: 'other.com',
          use: 'enc',
          alg: 'RSA-OAEP-256'
        }
      ];

      await sender.addRecipientData('other.com', { data: 'not for us' });
      const tacMessage = await sender.generateTACMessage();

      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Not a recipient')));
    });

    it('should handle wrong audience claim', async () => {
      // Create a signed JWT with wrong audience and then encrypt it
      const wrongAudienceJWT = await new jose.SignJWT({
        data: { test: 'data' }
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('sender.com')
        .setAudience('wrong-audience.com') // Wrong audience
        .setExpirationTime('1h')
        .sign(senderKeys.privateKey);

      // Encrypt the signed JWT
      const wrongAudienceJWE = await new jose.CompactEncrypt(new TextEncoder().encode(wrongAudienceJWT))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
        .encrypt(recipientKeys.publicKey);

      const malformedMessage = {
        version: SCHEMA_VERSION,
        recipients: [{ kid: 'recipient.com', jwe: wrongAudienceJWE }]
      };
      const base64Message = Buffer.from(JSON.stringify(malformedMessage)).toString('base64');

      const senderJWK = await sender.getPublicJWK();
      recipient.fetchJWKS = async () => [senderJWK];

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('audience') || e.includes('aud')));
    });
  });

  describe('Decryption', () => {
    it('should successfully decrypt with correct private key', async () => {
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => [senderJWK];

      const testData = {
        user: {
          email: { address: 'test@example.com' },
          intent: 'Buy running shoes',
          preferences: ['comfort', 'durability']
        },
        session: {
          ipAddress: '192.168.1.1',
          timestamp: Date.now()
        }
      };

      await sender.addRecipientData('recipient.com', testData);
      const tacMessage = await sender.generateTACMessage();
      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, true);
      assert.deepStrictEqual(result.data, testData);
    });

    it('should fail with wrong private key', async () => {
      // Create another recipient with different keys
      const wrongRecipientKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const wrongRecipient = new TACRecipient({
        domain: 'recipient.com',
        privateKey: wrongRecipientKeys.privateKey
      });

      // Setup message for correct recipient
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      wrongRecipient.fetchJWKS = async () => [senderJWK];

      await sender.addRecipientData('recipient.com', { data: 'secret' });
      const tacMessage = await sender.generateTACMessage();

      // Try to process with wrong recipient
      const result = await wrongRecipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('decrypt')));
    });

    it('should handle key type mismatch', async () => {
      // This test simulates using RSA key for EC encryption (edge case)
      // In practice, this would be caught during message generation
      const ecRecipientKeys = await jose.generateKeyPair('ES256');
      const ecRecipient = new TACRecipient({
        domain: 'ec-recipient.com',
        privateKey: ecRecipientKeys.privateKey
      });

      // Manually create JWE with wrong algorithm
      const wrongJWE = await new jose.EncryptJWT({ data: 'test' })
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }) // RSA algorithm
        .setIssuer('sender.com')
        .setAudience('ec-recipient.com')
        .setExpirationTime('1h')
        .encrypt(recipientKeys.publicKey); // But encrypt with RSA key

      const malformedMessage = {
        version: SCHEMA_VERSION,
        recipients: [{ kid: 'ec-recipient.com', jwe: wrongJWE }]
      };
      const base64Message = Buffer.from(JSON.stringify(malformedMessage)).toString('base64');

      const senderJWK = await sender.getPublicJWK();
      ecRecipient.fetchJWKS = async () => [senderJWK];

      const result = await ecRecipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Invalid key') || e.includes('asymmetricKeyType')));
    });

    it('should handle corrupted ciphertext', async () => {
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => [senderJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      // Corrupt the message
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      // Corrupt the JWE by changing some characters
      const originalJWE = message.recipients[0].jwe;
      const corruptedJWE = originalJWE.substring(0, originalJWE.length - 10) + 'CORRUPTED!';
      message.recipients[0].jwe = corruptedJWE;

      const corruptedMessage = Buffer.from(JSON.stringify(message)).toString('base64');

      const result = await recipient.processTACMessage(corruptedMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('decrypt') || e.includes('Invalid')));
    });

    it('should fail when no private key loaded', async () => {
      // Create recipient without private key (edge case)
      const emptyRecipient = new TACRecipient({
        domain: 'recipient.com',
        privateKey: recipientKeys.privateKey // Will be cleared below
      });

      // Manually clear the private key to simulate missing key
      emptyRecipient.privateKey = null;

      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      emptyRecipient.fetchJWKS = async () => [senderJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      const result = await emptyRecipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('private key') || e.includes('decrypt')));
    });
  });

  describe('Signature Verification', () => {
    it('should verify valid signature', async () => {
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => [senderJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();
      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.issuer, 'sender.com');
    });

    it('should fail with invalid signature', async () => {
      const recipientJWK = await recipient.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      // Corrupt the signature by providing wrong sender public key
      const wrongSenderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const wrongSenderJWK = await jose.exportJWK(wrongSenderKeys.publicKey);
      recipient.fetchJWKS = async () => [wrongSenderJWK];

      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('signature') || e.includes('verify')));
    });

    it('should handle wrong sender key', async () => {
      const recipientJWK = await recipient.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      // Use different public key for verification
      const differentSenderKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const differentSenderJWK = await jose.exportJWK(differentSenderKeys.publicKey);
      recipient.fetchJWKS = async () => [differentSenderJWK];

      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('signature') || e.includes('verify')));
    });

    it('should handle expired JWT', async () => {
      // Manually create an expired JWT
      const expiredTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago

      const expiredJWT = await new jose.SignJWT({
        data: { test: 'data' }
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('sender.com')
        .setAudience('recipient.com')
        .setIssuedAt(expiredTime - 3600) // 2 hours ago
        .setExpirationTime(expiredTime) // 1 hour ago (clearly expired)
        .sign(senderKeys.privateKey);

      // Encrypt the expired JWT
      const expiredJWE = await new jose.CompactEncrypt(new TextEncoder().encode(expiredJWT))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
        .encrypt(recipientKeys.publicKey);

      const expiredMessage = {
        version: SCHEMA_VERSION,
        recipients: [{ kid: 'recipient.com', jwe: expiredJWE }]
      };
      const base64Message = Buffer.from(JSON.stringify(expiredMessage)).toString('base64');

      const senderJWK = await sender.getPublicJWK();
      recipient.fetchJWKS = async () => [senderJWK];

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('expired') || e.includes('exp')));
    });

    it('should handle not yet valid JWT (future iat)', async () => {
      // Manually create JWT with future iat
      const futureTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour in future

      // Create signed JWT with future iat
      const futureSignedJWT = await new jose.SignJWT({
        data: { test: 'data' }
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setIssuer('sender.com')
        .setAudience('recipient.com')
        .setIssuedAt(futureTime) // Future iat
        .setExpirationTime(futureTime + 3600)
        .sign(senderKeys.privateKey);

      // Encrypt the signed JWT
      const futureJWE = await new jose.CompactEncrypt(new TextEncoder().encode(futureSignedJWT))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
        .encrypt(recipientKeys.publicKey);

      const futureMessage = {
        version: SCHEMA_VERSION,
        recipients: [{ kid: 'recipient.com', jwe: futureJWE }]
      };
      const base64Message = Buffer.from(JSON.stringify(futureMessage)).toString('base64');

      const senderJWK = await sender.getPublicJWK();
      recipient.fetchJWKS = async () => [senderJWK];

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('not yet valid') || e.includes('iat')));
    });

    it('should handle missing issuer claim', async () => {
      // Manually create signed JWT without issuer
      const jwtWithoutIssuer = await new jose.SignJWT({
        data: { test: 'data' }
      })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
        .setAudience('recipient.com')
        .setExpirationTime('1h')
        // Missing setIssuer
        .sign(senderKeys.privateKey);

      // Encrypt the signed JWT
      const jweWithoutIssuer = await new jose.CompactEncrypt(new TextEncoder().encode(jwtWithoutIssuer))
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT' })
        .encrypt(recipientKeys.publicKey);

      const messageWithoutIssuer = {
        version: SCHEMA_VERSION,
        recipients: [{ kid: 'recipient.com', jwe: jweWithoutIssuer }]
      };
      const base64Message = Buffer.from(JSON.stringify(messageWithoutIssuer)).toString('base64');

      const senderJWK = await sender.getPublicJWK();
      recipient.fetchJWKS = async () => [senderJWK];

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('issuer') || e.includes('iss')));
    });

    it('should handle JWKS fetch failure', async () => {
      const recipientJWK = await recipient.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => {
        throw new Error('JWKS fetch failed');
      };

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();
      const result = await recipient.processTACMessage(tacMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('JWKS fetch failed')));
    });
  });

  describe('Multi-Recipient Messages', () => {
    it('should extract correct data from multi-recipient message', async () => {
      // Setup multiple recipients
      const recipient2Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipient2 = new TACRecipient({
        domain: 'recipient2.com',
        privateKey: recipient2Keys.privateKey
      });

      const recipientJWK = await recipient.getPublicJWK();
      const recipient2JWK = await recipient2.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async domain => {
        if (domain === 'recipient.com') {
          return [recipientJWK];
        }
        if (domain === 'recipient2.com') {
          return [recipient2JWK];
        }
        throw new Error('Unknown domain');
      };

      recipient.fetchJWKS = async () => [senderJWK];
      recipient2.fetchJWKS = async () => [senderJWK];

      await sender.setRecipientsData({
        'recipient.com': {
          user: { email: { address: 'user1@example.com' } },
          secret: 'recipient1-secret'
        },
        'recipient2.com': {
          user: { email: { address: 'user2@example.com' } },
          secret: 'recipient2-secret'
        }
      });

      const tacMessage = await sender.generateTACMessage();

      // Both recipients should be able to process
      const result1 = await recipient.processTACMessage(tacMessage);
      const result2 = await recipient2.processTACMessage(tacMessage);

      // Verify both are valid
      assert.strictEqual(result1.valid, true);
      assert.strictEqual(result2.valid, true);

      // Verify they see all recipients
      assert.deepStrictEqual(result1.recipients, ['recipient.com', 'recipient2.com']);
      assert.deepStrictEqual(result2.recipients, ['recipient.com', 'recipient2.com']);

      // Verify data isolation - each sees only their data
      assert.strictEqual(result1.data.secret, 'recipient1-secret');
      assert.strictEqual(result1.data.user.email.address, 'user1@example.com');

      assert.strictEqual(result2.data.secret, 'recipient2-secret');
      assert.strictEqual(result2.data.user.email.address, 'user2@example.com');
    });

    it('should handle large number of recipients', async () => {
      const numRecipients = 10;
      const recipients = [];
      const recipientData = {};

      // Create multiple recipients
      for (let i = 1; i <= numRecipients; i++) {
        const domain = `recipient${i}.com`;
        const keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const recipientInstance = new TACRecipient({
          domain: domain,
          privateKey: keys.privateKey
        });
        recipients.push({ domain, instance: recipientInstance, keys });
        recipientData[domain] = { id: i, data: `data for recipient ${i}` };
      }

      // Setup sender JWKS fetch
      sender.fetchJWKS = async domain => {
        const recipient = recipients.find(r => r.domain === domain);
        if (recipient) {
          const jwk = await jose.exportJWK(recipient.keys.publicKey);
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

      // Setup recipients JWKS fetch
      const senderJWK = await sender.getPublicJWK();
      recipients.forEach(({ instance }) => {
        instance.fetchJWKS = async () => [senderJWK];
      });

      await sender.setRecipientsData(recipientData);
      const tacMessage = await sender.generateTACMessage();

      // Each recipient should be able to process and get their data
      for (const { domain, instance } of recipients) {
        const result = await instance.processTACMessage(tacMessage);

        assert.strictEqual(result.valid, true);
        assert.strictEqual(result.recipients.length, numRecipients);
        assert.ok(result.recipients.includes(domain));

        const expectedId = parseInt(domain.match(/\d+/)[0]);
        assert.strictEqual(result.data.id, expectedId);
        assert.strictEqual(result.data.data, `data for recipient ${expectedId}`);
      }
    });

    it('should ensure recipient data isolation', async () => {
      // Test that each recipient can only see their own data, not other recipients' data

      // Setup merchant and vendor recipients
      const merchantKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const vendorKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const merchant = new TACRecipient({
        domain: 'merchant.com',
        privateKey: merchantKeys.privateKey
      });

      const vendor = new TACRecipient({
        domain: 'vendor.com',
        privateKey: vendorKeys.privateKey
      });

      // Get public keys for encryption
      const merchantJWK = await merchant.getPublicJWK();
      const vendorJWK = await vendor.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      // Setup JWKS fetching
      sender.fetchJWKS = async domain => {
        if (domain === 'merchant.com') {
          return [merchantJWK];
        }
        if (domain === 'vendor.com') {
          return [vendorJWK];
        }
        throw new Error(`Unknown domain: ${domain}`);
      };

      // Both recipients fetch sender's public key for signature verification
      merchant.fetchJWKS = async () => [senderJWK];
      vendor.fetchJWKS = async () => [senderJWK];

      // Add DIFFERENT sensitive data for each recipient
      /* eslint-disable camelcase */
      await sender.addRecipientData('merchant.com', {
        customer_id: 'cust_12345',
        payment_method: 'visa_ending_4242',
        amount: 150.0,
        currency: 'USD',
        merchant_secret: 'TOP_SECRET_MERCHANT_DATA',
        merchant_commission: 5.5
      });

      await sender.addRecipientData('vendor.com', {
        customer_id: 'cust_12345',
        shipping_address: '123 Main St, Secure City, SC 12345',
        product_skus: ['SECRET_SKU_001', 'SECRET_SKU_002'],
        vendor_secret: 'TOP_SECRET_VENDOR_DATA',
        vendor_cost: 125.0
      });
      /* eslint-enable camelcase */

      // Generate the multi-recipient message
      const tacMessage = await sender.generateTACMessage();

      // Merchant processes the message
      const merchantResult = await merchant.processTACMessage(tacMessage);
      assert.strictEqual(merchantResult.valid, true);
      assert.strictEqual(merchantResult.issuer, 'sender.com');

      // Merchant should ONLY see merchant data
      assert.strictEqual(merchantResult.data.customer_id, 'cust_12345');
      assert.strictEqual(merchantResult.data.payment_method, 'visa_ending_4242');
      assert.strictEqual(merchantResult.data.amount, 150.0);
      assert.strictEqual(merchantResult.data.merchant_secret, 'TOP_SECRET_MERCHANT_DATA');
      assert.strictEqual(merchantResult.data.merchant_commission, 5.5);

      // Merchant should NOT see vendor data
      assert.strictEqual(merchantResult.data.shipping_address, undefined);
      assert.strictEqual(merchantResult.data.product_skus, undefined);
      assert.strictEqual(merchantResult.data.vendor_secret, undefined);
      assert.strictEqual(merchantResult.data.vendor_cost, undefined);

      // Vendor processes the SAME message
      const vendorResult = await vendor.processTACMessage(tacMessage);
      assert.strictEqual(vendorResult.valid, true);
      assert.strictEqual(vendorResult.issuer, 'sender.com');

      // Vendor should ONLY see vendor data
      assert.strictEqual(vendorResult.data.customer_id, 'cust_12345');
      assert.strictEqual(vendorResult.data.shipping_address, '123 Main St, Secure City, SC 12345');
      assert.deepStrictEqual(vendorResult.data.product_skus, ['SECRET_SKU_001', 'SECRET_SKU_002']);
      assert.strictEqual(vendorResult.data.vendor_secret, 'TOP_SECRET_VENDOR_DATA');
      assert.strictEqual(vendorResult.data.vendor_cost, 125.0);

      // Vendor should NOT see merchant data
      assert.strictEqual(vendorResult.data.payment_method, undefined);
      assert.strictEqual(vendorResult.data.amount, undefined);
      assert.strictEqual(vendorResult.data.merchant_secret, undefined);
      assert.strictEqual(vendorResult.data.merchant_commission, undefined);

      // Both should be able to verify the sender but see different data
      assert.strictEqual(merchantResult.issuer, vendorResult.issuer); // Same sender
      assert.notDeepStrictEqual(merchantResult.data, vendorResult.data); // Different data
    });

    it('should prevent cross-recipient data leakage in large messages', async () => {
      // Test with multiple recipients to ensure no data leakage
      const recipients = [];
      const recipientData = {};

      // Create 5 different recipients
      for (let i = 1; i <= 5; i++) {
        const keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
        const domain = `recipient${i}.com`;
        const instance = new TACRecipient({
          domain,
          privateKey: keys.privateKey
        });

        recipients.push({ domain, instance, keys });

        // Each recipient gets unique sensitive data
        /* eslint-disable camelcase */
        recipientData[domain] = {
          recipient_id: i,
          secret_data: `CONFIDENTIAL_DATA_FOR_RECIPIENT_${i}`,
          private_key_hint: `hint_${i}_${Math.random().toString(36).substring(7)}`,
          sensitive_amount: i * 1000.5
        };
        /* eslint-enable camelcase */
      }

      // Setup sender to encrypt for all recipients
      sender.fetchJWKS = async domain => {
        const recipient = recipients.find(r => r.domain === domain);
        if (!recipient) {
          throw new Error(`Unknown domain: ${domain}`);
        }

        const jwk = await jose.exportJWK(recipient.keys.publicKey);
        return [{ ...jwk, kid: domain }];
      };

      // Add data for all recipients
      for (const [domain, data] of Object.entries(recipientData)) {
        await sender.addRecipientData(domain, data);
      }

      const senderJWK = await sender.getPublicJWK();
      const tacMessage = await sender.generateTACMessage();

      // Each recipient should only see their own data
      for (const { domain, instance } of recipients) {
        instance.fetchJWKS = async () => [senderJWK];

        const result = await instance.processTACMessage(tacMessage);
        assert.strictEqual(result.valid, true);

        const expectedData = recipientData[domain];

        // Should see own data
        assert.strictEqual(result.data.recipient_id, expectedData.recipient_id);
        assert.strictEqual(result.data.secret_data, expectedData.secret_data);
        assert.strictEqual(result.data.private_key_hint, expectedData.private_key_hint);
        assert.strictEqual(result.data.sensitive_amount, expectedData.sensitive_amount);

        // Should NOT see any other recipient's data
        for (const [otherDomain, otherData] of Object.entries(recipientData)) {
          if (otherDomain !== domain) {
            // Ensure no cross-contamination
            assert.notStrictEqual(result.data.secret_data, otherData.secret_data);
            assert.notStrictEqual(result.data.private_key_hint, otherData.private_key_hint);
            assert.notStrictEqual(result.data.sensitive_amount, otherData.sensitive_amount);
          }
        }
      }
    });

    it('should fail when recipient tries to decrypt another recipients message', async () => {
      // Test that merchant cannot use their private key to decrypt vendor's JWE

      const merchantKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const vendorKeys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const merchant = new TACRecipient({
        domain: 'merchant.com',
        privateKey: merchantKeys.privateKey
      });

      const vendor = new TACRecipient({
        domain: 'vendor.com',
        privateKey: vendorKeys.privateKey
      });

      const merchantJWK = await merchant.getPublicJWK();
      const vendorJWK = await vendor.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async domain => {
        if (domain === 'merchant.com') {
          return [merchantJWK];
        }
        if (domain === 'vendor.com') {
          return [vendorJWK];
        }
        throw new Error(`Unknown domain: ${domain}`);
      };

      merchant.fetchJWKS = async () => [senderJWK];
      vendor.fetchJWKS = async () => [senderJWK];

      // Only add data for vendor, not merchant
      /* eslint-disable camelcase */
      await sender.addRecipientData('vendor.com', {
        vendor_only_data: 'This should only be readable by vendor',
        secret: 'TOP_SECRET_VENDOR_INFO'
      });
      /* eslint-enable camelcase */

      const tacMessage = await sender.generateTACMessage();

      // Vendor should be able to read the message
      const vendorResult = await vendor.processTACMessage(tacMessage);
      assert.strictEqual(vendorResult.valid, true);
      assert.strictEqual(vendorResult.data.vendor_only_data, 'This should only be readable by vendor');

      // Merchant should NOT be able to read the message (not a recipient)
      const merchantResult = await merchant.processTACMessage(tacMessage);
      assert.strictEqual(merchantResult.valid, false);
      assert.ok(merchantResult.errors.some(e => e.includes('Not a recipient') || e.includes('merchant.com')));
      assert.strictEqual(merchantResult.data, null);
    });
  });

  describe('Static Inspection Methods', () => {
    it('should inspect message without decryption', async () => {
      const recipientJWK = await recipient.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      const info = TACRecipient.inspect(tacMessage);

      assert.strictEqual(info.version, SCHEMA_VERSION);
      assert.deepStrictEqual(info.recipients, ['recipient.com']);
    });

    it('should inspect multi-recipient message', async () => {
      const recipient1Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const recipient2Keys = await jose.generateKeyPair('RS256', { modulusLength: 2048 });

      const recipient1JWK = await jose.exportJWK(recipient1Keys.publicKey);
      const recipient2JWK = await jose.exportJWK(recipient2Keys.publicKey);

      sender.fetchJWKS = async domain => {
        if (domain === 'merchant.com') {
          return [
            {
              ...recipient1JWK,
              kid: 'merchant.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        } else if (domain === 'forter.com') {
          return [
            {
              ...recipient2JWK,
              kid: 'forter.com',
              use: 'enc',
              alg: 'RSA-OAEP-256'
            }
          ];
        }
        throw new Error('Unknown domain');
      };

      await sender.setRecipientsData({
        'merchant.com': { data: 'for merchant' },
        'forter.com': { data: 'for forter' }
      });

      const tacMessage = await sender.generateTACMessage();
      const info = TACRecipient.inspect(tacMessage);

      assert.strictEqual(info.version, SCHEMA_VERSION);
      assert.strictEqual(info.recipients.length, 2);
      assert.ok(info.recipients.includes('merchant.com'));
      assert.ok(info.recipients.includes('forter.com'));
    });

    it('should handle invalid message in inspect', () => {
      const result = TACRecipient.inspect('invalid-base64!');
      assert.ok(result.error && result.error.includes('Invalid TAC-Protocol message format'));
    });

    it('should handle malformed JSON in inspect', () => {
      const invalidJson = '{ invalid json }';
      const base64Invalid = Buffer.from(invalidJson).toString('base64');

      const result = TACRecipient.inspect(base64Invalid);
      assert.ok(result.error && result.error.includes('Invalid TAC-Protocol message format'));
    });
  });

  describe('Error Recovery and Edge Cases', () => {
    it('should handle partially corrupted message', async () => {
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => [senderJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      // Corrupt part of the base64 message
      const corruptedMessage = tacMessage.substring(0, tacMessage.length - 20) + 'X'.repeat(20);

      const result = await recipient.processTACMessage(corruptedMessage);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.length > 0);
    });

    it('should handle empty recipients array', async () => {
      const emptyMessage = {
        version: SCHEMA_VERSION,
        recipients: []
      };
      const base64Message = Buffer.from(JSON.stringify(emptyMessage)).toString('base64');

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Not a recipient')));
    });

    it('should handle recipients with missing fields', async () => {
      const malformedMessage = {
        version: SCHEMA_VERSION,
        recipients: [
          { kid: 'recipient.com' }, // Missing jwe
          { jwe: 'some-jwe-data' } // Missing kid
        ]
      };
      const base64Message = Buffer.from(JSON.stringify(malformedMessage)).toString('base64');

      const result = await recipient.processTACMessage(base64Message);

      assert.strictEqual(result.valid, false);
      assert.ok(
        result.errors.some(
          e =>
            e.includes('Not a recipient') || e.includes('Invalid message') || e.includes('decrypt') || e.includes('JWE')
        )
      );
    });

    it('should handle very large number of recipients in message', async () => {
      // Create message with many recipients (but we're only one of them)
      const recipients = [];
      for (let i = 1; i <= 100; i++) {
        recipients.push({
          kid: `recipient${i}.com`,
          jwe: 'fake-jwe-data-' + i
        });
      }

      // Add our recipient
      const recipientJWK = await recipient.getPublicJWK();
      const senderJWK = await sender.getPublicJWK();

      sender.fetchJWKS = async () => [recipientJWK];
      recipient.fetchJWKS = async () => [senderJWK];

      await sender.addRecipientData('recipient.com', { data: 'test' });
      const tacMessage = await sender.generateTACMessage();

      // Decode, add fake recipients, re-encode
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);
      message.recipients = [...message.recipients, ...recipients];
      const modifiedMessage = Buffer.from(JSON.stringify(message)).toString('base64');

      const result = await recipient.processTACMessage(modifiedMessage);

      // Should still work - should find our recipient among the many
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.data.data, 'test');
    });

    it('should provide meaningful error messages', async () => {
      const tests = [
        {
          input: null,
          expectedError: 'Missing TAC-Protocol message'
        },
        {
          input: '',
          expectedError: 'Missing TAC-Protocol message'
        },
        {
          input: 'invalid-base64!',
          expectedError: 'Invalid TAC-Protocol message format'
        }
      ];

      for (const { input, expectedError } of tests) {
        const result = await recipient.processTACMessage(input);
        assert.strictEqual(result.valid, false);
        assert.ok(
          result.errors.some(e => e.includes(expectedError)),
          `Expected error containing "${expectedError}" or similar, got: ${result.errors.join(', ')}`
        );
      }
    });
  });
});
