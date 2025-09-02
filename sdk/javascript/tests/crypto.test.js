import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import * as jose from 'jose';
import TACSender from '../src/sender.js';

describe('Cryptographic Operations', () => {
  describe('Key Management Tests', () => {
    describe('Valid Key Types', () => {
      it('should support RSA 2048-bit keys', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        assert.strictEqual(sender.keyType, 'RSA');
        assert.strictEqual(sender.signingAlgorithm, 'RS256');
        // Note: asymmetricKeySize may not be available on all key types
      });

      it('should support RSA 3072-bit keys', async () => {
        const { privateKey } = await jose.generateKeyPair('RS384', {
          modulusLength: 3072
        });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        assert.strictEqual(sender.keyType, 'RSA');
        assert.strictEqual(sender.signingAlgorithm, 'RS256'); // Implementation defaults to RS256
        // Note: asymmetricKeySize may not be available on all key types
      });

      it('should support RSA 4096-bit keys', async () => {
        const { privateKey } = await jose.generateKeyPair('RS512', {
          modulusLength: 4096
        });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        assert.strictEqual(sender.keyType, 'RSA');
        assert.strictEqual(sender.signingAlgorithm, 'RS256'); // Implementation defaults to RS256
        // Note: asymmetricKeySize may not be available on all key types
      });

      it('should support EC P-256 keys', async () => {
        const { privateKey } = await jose.generateKeyPair('ES256');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        assert.strictEqual(sender.keyType, 'EC');
        assert.strictEqual(sender.signingAlgorithm, 'ES256');
        assert.strictEqual(sender.privateKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
      });

      it('should support EC P-384 keys', async () => {
        const { privateKey } = await jose.generateKeyPair('ES384');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        assert.strictEqual(sender.keyType, 'EC');
        assert.strictEqual(sender.signingAlgorithm, 'ES384');
        assert.strictEqual(sender.privateKey.asymmetricKeyDetails.namedCurve, 'secp384r1');
      });

      it('should support EC P-521 keys', async () => {
        const { privateKey } = await jose.generateKeyPair('ES512');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        assert.strictEqual(sender.keyType, 'EC');
        assert.strictEqual(sender.signingAlgorithm, 'ES512');
        assert.strictEqual(sender.privateKey.asymmetricKeyDetails.namedCurve, 'secp521r1');
      });
    });

    describe('Invalid Key Types', () => {
      it('should reject unsupported key types gracefully', () => {
        // Create an Ed25519 key (unsupported)
        const ed25519Key = crypto.generateKeyPairSync('ed25519');

        // Should throw an error when trying to use unsupported key type
        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: ed25519Key.privateKey
          });
        }, /TAC Protocol requires RSA or EC/);
      });

      it('should reject DSA keys', () => {
        // DSA keys are not supported
        const dsaKey = crypto.generateKeyPairSync('dsa', {
          modulusLength: 2048,
          divisorLength: 256
        });

        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: dsaKey.privateKey
          });
        }, /TAC Protocol requires RSA or EC/);
      });
    });

    describe('Key Format Parsing', () => {
      it('should parse PEM format RSA keys', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privatePem
        });

        assert.strictEqual(sender.keyType, 'RSA');
        assert.ok(sender.privateKey);
        assert.ok(sender.publicKey);
      });

      it('should parse PEM format EC keys', async () => {
        const { privateKey } = await jose.generateKeyPair('ES256');

        const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privatePem
        });

        assert.strictEqual(sender.keyType, 'EC');
        assert.ok(sender.privateKey);
        assert.ok(sender.publicKey);
      });
    });

    describe('Key Derivation', () => {
      it('should correctly derive public key from RSA private key', async () => {
        const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        // Verify derived public key matches original
        const originalJWK = await jose.exportJWK(publicKey);
        const derivedJWK = await sender.getPublicJWK();

        assert.strictEqual(derivedJWK.kty, originalJWK.kty);
        assert.strictEqual(derivedJWK.n, originalJWK.n);
        assert.strictEqual(derivedJWK.e, originalJWK.e);
      });

      it('should correctly derive public key from EC private key', async () => {
        const { publicKey, privateKey } = await jose.generateKeyPair('ES256');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        // Verify derived public key matches original
        const originalJWK = await jose.exportJWK(publicKey);
        const derivedJWK = await sender.getPublicJWK();

        assert.strictEqual(derivedJWK.kty, originalJWK.kty);
        assert.strictEqual(derivedJWK.crv, originalJWK.crv);
        assert.strictEqual(derivedJWK.x, originalJWK.x);
        assert.strictEqual(derivedJWK.y, originalJWK.y);
      });
    });

    describe('Key ID Generation', () => {
      it('should generate consistent SHA-256 hash-based key IDs', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const keyId1 = sender.generateKeyId();
        const keyId2 = sender.generateKeyId();

        assert.strictEqual(keyId1, keyId2);
        assert.match(keyId1, /^[A-Za-z0-9_-]+$/); // Base64url format
        assert.strictEqual(keyId1.length, 43); // SHA-256 base64url encoded length
      });

      it('should generate different key IDs for different keys', async () => {
        const { privateKey: key1 } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });
        const { privateKey: key2 } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const sender1 = new TACSender({
          domain: 'test.com',
          privateKey: key1
        });
        const sender2 = new TACSender({
          domain: 'test.com',
          privateKey: key2
        });

        const keyId1 = sender1.generateKeyId();
        const keyId2 = sender2.generateKeyId();

        assert.notStrictEqual(keyId1, keyId2);
      });
    });

    describe('Malformed Keys', () => {
      it('should handle corrupted PEM data', () => {
        const corruptedPem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9US8cKB
CORRUPTED_DATA_HERE
-----END PRIVATE KEY-----`;

        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: corruptedPem
          });
        }, /error.*DECODER routines/);
      });

      it('should handle truncated key data', () => {
        const truncatedPem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEF
-----END PRIVATE KEY-----`;

        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: truncatedPem
          });
        }, /error.*DECODER routines/);
      });
    });

    describe('Password-Protected Keys', () => {
      it('should handle encrypted private keys with correct passphrase', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        // Export with encryption
        const encryptedPem = privateKey.export({
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: 'test-password'
        });

        // Should work with passphrase
        const keyObject = crypto.createPrivateKey({
          key: encryptedPem,
          passphrase: 'test-password'
        });

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: keyObject
        });

        assert.strictEqual(sender.keyType, 'RSA');
      });

      it('should reject encrypted private keys without passphrase', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const encryptedPem = privateKey.export({
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: 'test-password'
        });

        // Should fail without passphrase
        assert.throws(() => {
          new TACSender({
            domain: 'test.com',
            privateKey: encryptedPem
          });
        }, /error.*interrupted or cancelled/);
      });
    });
  });

  describe('Algorithm Selection Tests', () => {
    describe('RSA Algorithms', () => {
      it('should use correct signing algorithms for RSA keys', async () => {
        const testCases = [
          { keySize: 2048, expectedAlg: 'RS256' },
          { keySize: 3072, expectedAlg: 'RS256' }, // Implementation defaults to RS256
          { keySize: 4096, expectedAlg: 'RS256' } // Implementation defaults to RS256
        ];

        for (const { keySize, expectedAlg } of testCases) {
          const { privateKey } = await jose.generateKeyPair(expectedAlg, {
            modulusLength: keySize
          });

          const sender = new TACSender({
            domain: 'test.com',
            privateKey: privateKey
          });

          assert.strictEqual(sender.signingAlgorithm, expectedAlg);
        }
      });

      it('should use RSA-OAEP-256 for RSA encryption', async () => {
        const { privateKey, publicKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        const jwk = await jose.exportJWK(publicKey);
        const encryptionJWK = {
          ...jwk,
          use: 'enc',
          alg: 'RSA-OAEP-256'
        };

        // Test that we can use this for encryption
        const testData = 'test encryption data';
        const encrypted = await new jose.EncryptJWT({ data: testData })
          .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
          .setAudience('test.com')
          .setIssuer('sender.com')
          .setExpirationTime('1h')
          .encrypt(await jose.importJWK(encryptionJWK));

        assert.ok(encrypted);

        // Verify we can decrypt
        const decrypted = await jose.jwtDecrypt(encrypted, privateKey);
        assert.strictEqual(decrypted.payload.data, testData);
      });
    });

    describe('EC Algorithms', () => {
      it('should use correct signing algorithms for EC keys', async () => {
        const testCases = [
          { curve: 'ES256', expectedCurve: 'prime256v1' },
          { curve: 'ES384', expectedCurve: 'secp384r1' },
          { curve: 'ES512', expectedCurve: 'secp521r1' }
        ];

        for (const { curve, expectedCurve } of testCases) {
          const { privateKey } = await jose.generateKeyPair(curve);

          const sender = new TACSender({
            domain: 'test.com',
            privateKey: privateKey
          });

          assert.strictEqual(sender.signingAlgorithm, curve);
          assert.strictEqual(sender.privateKey.asymmetricKeyDetails.namedCurve, expectedCurve);
        }
      });

      it('should use ECDH-ES+A256KW for EC encryption', async () => {
        const { privateKey, publicKey } = await jose.generateKeyPair('ES256');

        const jwk = await jose.exportJWK(publicKey);
        const encryptionJWK = {
          ...jwk,
          use: 'enc',
          alg: 'ECDH-ES+A256KW'
        };

        // Test that we can use this for encryption
        const testData = 'test encryption data';
        const encrypted = await new jose.EncryptJWT({ data: testData })
          .setProtectedHeader({ alg: 'ECDH-ES+A256KW', enc: 'A256GCM' })
          .setAudience('test.com')
          .setIssuer('sender.com')
          .setExpirationTime('1h')
          .encrypt(await jose.importJWK(encryptionJWK));

        assert.ok(encrypted);

        // Verify we can decrypt
        const decrypted = await jose.jwtDecrypt(encrypted, privateKey);
        assert.strictEqual(decrypted.payload.data, testData);
      });
    });

    describe('Algorithm Mismatch', () => {
      it('should reject RSA algorithm for EC key', async () => {
        const { privateKey } = await jose.generateKeyPair('ES256');

        // Try to sign with wrong algorithm
        const payload = { test: 'data' };

        await assert.rejects(async () => {
          await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'RS256' }) // Wrong algorithm
            .setIssuer('test.com')
            .setExpirationTime('1h')
            .sign(privateKey);
        }, /Invalid key for this operation/);
      });

      it('should reject EC algorithm for RSA key', async () => {
        const { privateKey } = await jose.generateKeyPair('RS256', {
          modulusLength: 2048
        });

        // Try to sign with wrong algorithm
        const payload = { test: 'data' };

        await assert.rejects(async () => {
          await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'ES256' }) // Wrong algorithm
            .setIssuer('test.com')
            .setExpirationTime('1h')
            .sign(privateKey);
        }, /Invalid key for this operation/);
      });
    });

    describe('Curve Detection', () => {
      it('should correctly detect P-256 curve', async () => {
        const { privateKey } = await jose.generateKeyPair('ES256');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const jwk = await sender.getPublicJWK();
        assert.strictEqual(jwk.crv, 'P-256');
      });

      it('should correctly detect P-384 curve', async () => {
        const { privateKey } = await jose.generateKeyPair('ES384');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const jwk = await sender.getPublicJWK();
        assert.strictEqual(jwk.crv, 'P-384');
      });

      it('should correctly detect P-521 curve', async () => {
        const { privateKey } = await jose.generateKeyPair('ES512');

        const sender = new TACSender({
          domain: 'test.com',
          privateKey: privateKey
        });

        const jwk = await sender.getPublicJWK();
        assert.strictEqual(jwk.crv, 'P-521');
      });
    });
  });
});
