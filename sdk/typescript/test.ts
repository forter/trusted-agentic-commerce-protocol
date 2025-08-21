import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import * as jose from 'jose';
import TACSender from './sender.js';
import TACRecipient from './recipient.js';
import {
  JWKSCache,
  findEncryptionKey,
  findSigningKey
} from './utils.js';
import { JWK } from './sdk-types.js';

// Helper function to generate RSA key pairs for testing
async function generateRSAKeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
  return { publicKey, privateKey };
}

describe('Trusted Agentic Commerce Protocol - TypeScript SDK', () => {
  
  describe('TACSender', () => {
    let senderKeys: any;
    let sender: TACSender;

    beforeEach(async () => {
      senderKeys = await generateRSAKeyPair();
      sender = new TACSender({
        domain: 'agent.example.com',
        privateKey: senderKeys.privateKey,
        ttl: 3600
      });
    });

    it('should require domain and privateKey in constructor', () => {
      assert.throws(() => new TACSender({} as any), /domain is required/);
      assert.throws(() => new TACSender({ domain: 'test.com' } as any), /privateKey is required/);
    });

    it('should initialize with RSA keys and derive public key', () => {
      assert.strictEqual(sender.domain, 'agent.example.com');
      assert.ok((sender as any).privateKey);
      assert.ok((sender as any).publicKey);
      assert.strictEqual((sender as any).privateKey.asymmetricKeyType, 'rsa');
      assert.strictEqual((sender as any).publicKey.asymmetricKeyType, 'rsa');
    });

    it('should reject non-RSA keys', async () => {
      const ecKeys = await jose.generateKeyPair('ES256');
      assert.throws(() => new TACSender({
        domain: 'test.com',
        privateKey: ecKeys.privateKey as any
      }), /TAC Protocol requires RSA keys/);
    });

    it('should generate consistent key IDs', () => {
      const keyId1 = sender.generateKeyId();
      const keyId2 = sender.generateKeyId();
      
      assert.strictEqual(keyId1, keyId2);
      assert.match(keyId1, /^[A-Za-z0-9_-]+$/); // Base64url format
    });

    it('should add recipient data', () => {
      sender.addRecipientData('merchant.com', {
        user: { email: { address: 'test@example.com' } }
      });
      
      assert.deepStrictEqual((sender as any).recipientData['merchant.com'], {
        user: { email: { address: 'test@example.com' } }
      });
    });

    it('should set recipients data (clearing existing)', () => {
      // Add some initial data
      sender.addRecipientData('old.com', { test: 'data' });
      
      // Set new data (should clear old)
      sender.setRecipientsData({
        'merchant.com': { user: { email: { address: 'test@example.com' } } },
        'forter.com': { session: { ipAddress: '1.2.3.4', intent: 'Buy shoes' } }
      });
      
      assert.strictEqual(Object.keys((sender as any).recipientData).length, 2);
      assert.deepStrictEqual((sender as any).recipientData['merchant.com'], {
        user: { email: { address: 'test@example.com' } }
      });
      assert.deepStrictEqual((sender as any).recipientData['forter.com'], {
        session: { ipAddress: '1.2.3.4', intent: 'Buy shoes' }
      });
      assert.strictEqual((sender as any).recipientData['old.com'], undefined);
    });

    it('should clear recipient data', () => {
      sender.addRecipientData('test.com', { data: 'test' });
      sender.clearRecipientData();
      
      assert.deepStrictEqual((sender as any).recipientData, {});
    });

    it('should export public key as JWK', async () => {
      const jwk = await sender.getPublicJWK();
      
      assert.strictEqual(jwk.kty, 'RSA');
      assert.strictEqual(jwk.use, 'sig');
      assert.strictEqual(jwk.alg, 'RS256');
      assert.ok(jwk.kid);
      assert.ok(jwk.n);
      assert.ok(jwk.e);
    });

    it('should generate TAC message with proper structure', async () => {
      // Mock recipient keys
      const recipientKeys = await generateRSAKeyPair();
      const recipientJWK = await jose.exportJWK(recipientKeys.publicKey);
      
      // Mock JWKS fetch
      (sender as any).fetchJWKS = async () => [{ ...recipientJWK, kid: 'merchant.com', use: 'enc', alg: 'RSA-OAEP-256' }];
      
      sender.addRecipientData('merchant.com', {
        user: {
          email: { address: 'test@example.com' }
        },
        session: {
          intent: 'Find running shoes',
          consent: 'Buy Nike Air Jordan under $200'
        }
      });

      const tacMessage = await sender.generateTACMessage();
      
      // Should be valid JSON (JWE General format)
      const jwe = JSON.parse(tacMessage);
      assert.ok(jwe.protected);
      assert.ok(jwe.recipients);
      assert.ok(jwe.iv);
      assert.ok(jwe.ciphertext);
      assert.ok(jwe.tag);
      assert.strictEqual(jwe.unprotected.v, '2025-08-21');
      
      // Should have recipient
      assert.strictEqual(jwe.recipients.length, 1);
      assert.strictEqual(jwe.recipients[0].header.kid, 'merchant.com');
    });

    it('should fail to generate TAC message without recipient data', async () => {
      await assert.rejects(
        async () => await sender.generateTACMessage(),
        /No recipient data added/
      );
    });
  });

  describe('TACRecipient', () => {
    let recipientKeys: any;
    let recipient: TACRecipient;

    beforeEach(async () => {
      recipientKeys = await generateRSAKeyPair();
      recipient = new TACRecipient({
        domain: 'merchant.com',
        privateKey: recipientKeys.privateKey
      });
    });

    it('should require domain and privateKey in constructor', () => {
      assert.throws(() => new TACRecipient({} as any), /domain is required/);
      assert.throws(() => new TACRecipient({ domain: 'test.com' } as any), /privateKey is required/);
    });

    it('should initialize with RSA keys', () => {
      assert.strictEqual(recipient.domain, 'merchant.com');
      assert.ok((recipient as any).privateKey);
      assert.ok((recipient as any).publicKey);
      assert.strictEqual((recipient as any).privateKey.asymmetricKeyType, 'rsa');
    });

    it('should export public key as encryption JWK', async () => {
      const jwk = await recipient.getPublicJWK();
      
      assert.strictEqual(jwk.kty, 'RSA');
      assert.strictEqual(jwk.use, 'enc');
      assert.strictEqual(jwk.alg, 'RSA-OAEP-256');
      assert.ok(jwk.kid);
      assert.ok(jwk.n);
      assert.ok(jwk.e);
    });

    it('should process missing TAC message', async () => {
      const result = await recipient.processTACMessage();
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.includes('Missing TAC-Protocol message'));
    });

    it('should process invalid TAC message format', async () => {
      const result = await recipient.processTACMessage('invalid-json');
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Invalid TAC-Protocol message format')));
    });

    it('should inspect TAC message without decryption', () => {
      const mockJWE = {
        unprotected: { v: '2025-08-21' },
        recipients: [
          { header: { kid: 'merchant.com', alg: 'RSA-OAEP-256' } },
          { header: { kid: 'forter.com', alg: 'RSA-OAEP-256' } }
        ]
      };

      const info = TACRecipient.inspect(JSON.stringify(mockJWE));
      
      assert.strictEqual(info.version, '2025-08-21');
      assert.deepStrictEqual(info.recipients, ['merchant.com', 'forter.com']);
    });
  });

  describe('End-to-End Integration', () => {
    let senderKeys: any, recipientKeys: any, forterKeys: any;
    let sender: TACSender, merchant: TACRecipient, forter: TACRecipient;

    beforeEach(async () => {
      senderKeys = await generateRSAKeyPair();
      recipientKeys = await generateRSAKeyPair();
      forterKeys = await generateRSAKeyPair();

      sender = new TACSender({
        domain: 'agent.example.com',
        privateKey: senderKeys.privateKey
      });

      merchant = new TACRecipient({
        domain: 'merchant.com',
        privateKey: recipientKeys.privateKey
      });

      forter = new TACRecipient({
        domain: 'forter.com',
        privateKey: forterKeys.privateKey
      });
    });

    it('should work end-to-end with multiple recipients', async () => {
      // Mock JWKS fetching
      const senderJWK = await sender.getPublicJWK();
      const merchantJWK = await merchant.getPublicJWK();
      const forterJWK = await forter.getPublicJWK();

      (sender as any).fetchJWKS = async (domain: string) => {
        if (domain === 'merchant.com') return [merchantJWK];
        if (domain === 'forter.com') return [forterJWK];
        throw new Error(`Unknown domain: ${domain}`);
      };

      (merchant as any).fetchJWKS = async () => [senderJWK];
      (forter as any).fetchJWKS = async () => [senderJWK];

      // Set test data for multiple recipients
      sender.setRecipientsData({
        'merchant.com': {
          user: {
            email: { address: 'customer@example.com' }
          },
          session: {
            intent: 'Find reliable running shoes',
            consent: 'Buy Nike Air Jordan Retro under $200'
          }
        },
        'forter.com': {
          session: {
            ipAddress: '192.168.1.1',
            userAgent: 'MyAgent/1.0',
            forterToken: 'ftr_xyz'
          }
        }
      });

      // Generate TAC message
      const tacMessage = await sender.generateTACMessage();

      // Both recipients should be able to process it
      const merchantResult = await merchant.processTACMessage(tacMessage);
      const forterResult = await forter.processTACMessage(tacMessage);

      // Verify merchant result
      assert.strictEqual(merchantResult.valid, true);
      assert.strictEqual(merchantResult.issuer, 'agent.example.com');
      assert.ok(merchantResult.expires instanceof Date);
      assert.deepStrictEqual(merchantResult.recipients, ['merchant.com', 'forter.com']);
      
      // Merchant should see their data
      assert.deepStrictEqual(merchantResult.data, {
        user: {
          email: { address: 'customer@example.com' }
        },
        session: {
          intent: 'Find reliable running shoes',
          consent: 'Buy Nike Air Jordan Retro under $200'
        }
      });

      // Verify forter result
      assert.strictEqual(forterResult.valid, true);
      assert.strictEqual(forterResult.issuer, 'agent.example.com');
      assert.deepStrictEqual(forterResult.recipients, ['merchant.com', 'forter.com']);
      
      // Forter should see their data
      assert.deepStrictEqual(forterResult.data, {
        session: {
          ipAddress: '192.168.1.1',
          userAgent: 'MyAgent/1.0',
          forterToken: 'ftr_xyz'
        }
      });

      // Each recipient only sees their own data
      assert.ok(merchantResult.data.user);
      assert.ok(forterResult.data.session);
    });

    it('should handle non-recipient attempting to decrypt', async () => {
      const nonRecipientKeys = await generateRSAKeyPair();
      const nonRecipient = new TACRecipient({
        domain: 'unauthorized.com',
        privateKey: nonRecipientKeys.privateKey as any
      });

      // Setup sender with merchant as recipient
      const merchantJWK = await merchant.getPublicJWK();
      (sender as any).fetchJWKS = async () => [merchantJWK];
      
      sender.addRecipientData('merchant.com', { test: 'data' });
      const tacMessage = await sender.generateTACMessage();

      // Non-recipient should fail to process
      const result = await nonRecipient.processTACMessage(tacMessage);
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.errors.some(e => e.includes('Not a recipient')));
    });
  });

  describe('Utility Functions', () => {
    describe('JWKSCache', () => {
      let cache: JWKSCache;

      beforeEach(() => {
        cache = new JWKSCache(1000); // 1 second timeout
      });

      it('should cache and retrieve keys', () => {
        const keys: JWK[] = [{ kty: 'RSA', kid: 'test' }];
        
        cache.set('test.com', keys);
        assert.deepStrictEqual(cache.get('test.com'), keys);
      });

      it('should handle cache expiry', async () => {
        const keys: JWK[] = [{ kty: 'RSA', kid: 'test' }];
        
        cache.set('test.com', keys);
        assert.deepStrictEqual(cache.get('test.com'), keys);
        
        await new Promise(resolve => setTimeout(resolve, 1100));
        assert.strictEqual(cache.get('test.com'), null);
      });

      it('should clear cache', () => {
        const keys: JWK[] = [{ kty: 'RSA', kid: 'test' }];
        
        cache.set('test.com', keys);
        cache.set('example.com', keys);
        
        cache.clear('test.com');
        assert.strictEqual(cache.get('test.com'), null);
        assert.deepStrictEqual(cache.get('example.com'), keys);
        
        cache.clear();
        assert.strictEqual(cache.get('example.com'), null);
      });
    });

    describe('Key Finding Functions', () => {
      it('should find RSA encryption keys', () => {
        const keys: JWK[] = [
          { kty: 'EC', use: 'sig', alg: 'ES256', kid: 'ec-key' },
          { kty: 'RSA', use: 'enc', alg: 'RSA-OAEP-256', kid: 'rsa-enc', n: 'test', e: 'AQAB' },
          { kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'rsa-sig' }
        ];

        const encKey = findEncryptionKey(keys);
        assert.ok(encKey);
        assert.strictEqual(encKey.kid, 'rsa-enc');
        assert.strictEqual(encKey.use, 'enc');
        assert.strictEqual(encKey.kty, 'RSA');
      });

      it('should find RSA signing keys', () => {
        const keys: JWK[] = [
          { kty: 'EC', use: 'sig', alg: 'ES256', kid: 'ec-key' },
          { kty: 'RSA', use: 'enc', alg: 'RSA-OAEP-256', kid: 'rsa-enc' },
          { kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'rsa-sig', n: 'test', e: 'AQAB' }
        ];

        const sigKey = findSigningKey(keys, 'rsa-sig');
        assert.ok(sigKey);
        assert.strictEqual(sigKey.kid, 'rsa-sig');
        assert.strictEqual(sigKey.use, 'sig');
        assert.strictEqual(sigKey.kty, 'RSA');
      });

      it('should only return supported key types', () => {
        const keys: JWK[] = [
          { kty: 'OKP', use: 'sig', alg: 'EdDSA', kid: 'unsupported-key' }
        ];

        assert.strictEqual(findEncryptionKey(keys), undefined);
        assert.strictEqual(findSigningKey(keys), undefined);
      });
    });
  });
});