import crypto from 'node:crypto';
import * as jose from 'jose';
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findEncryptionKey,
  getKeyType,
  getAlgorithmForKey,
  publicKeyToJWK,
  getUserAgent
} from './utils.js';
import { SCHEMA_VERSION } from './version.js';
import { TACValidationError, TACCryptoError, TACNetworkError, TACErrorCodes } from './errors.js';

/**
 * TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
 * Creates JWT with issuer and expiration, encrypts data for multiple recipients
 */
class TACSender {
  /**
   * @param {Object} options - Configuration options
   * @param {string} options.domain - Domain of the agent (required, used as 'iss' in JWT)
   * @param {crypto.KeyObject|string} options.privateKey - Private key for signing (required)
   * @param {number} options.ttl - JWT expiry time in seconds (default: 3600)
   * @param {number} options.cacheTimeout - JWKS cache timeout in ms (default: 3600000)
   * @param {number} options.maxRetries - Max retry attempts for network requests (default: 3)
   * @param {number} options.retryDelay - Retry delay in ms (default: 1000)
   * @param {boolean} options.hideUserAgentVersion - If true, omit version details from User-Agent header (default: false)
   */
  constructor(options = {}) {
    if (!options.domain) {
      throw new TACValidationError('domain is required in TACSender constructor', TACErrorCodes.DOMAIN_REQUIRED);
    }
    if (!options.privateKey) {
      throw new TACValidationError(
        'privateKey is required in TACSender constructor',
        TACErrorCodes.PRIVATE_KEY_REQUIRED
      );
    }

    this.domain = options.domain;
    this.setPrivateKey(options.privateKey); // This sets both private and public keys
    this.ttl = options.ttl !== undefined ? options.ttl : 3600; // 1 hour default
    this.jwksCache = new JWKSCache(options.cacheTimeout || 3600000);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.hideUserAgentVersion = options.hideUserAgentVersion || false;
    this.recipientData = {}; // Store recipient data for later encryption
  }

  /**
   * Set private key and automatically derive public key
   * @param {crypto.KeyObject|string} privateKey - Private key object or PEM string
   * @private
   */
  setPrivateKey(privateKey) {
    try {
      if (typeof privateKey === 'string') {
        this.privateKey = crypto.createPrivateKey(privateKey);
      } else {
        this.privateKey = privateKey;
      }
    } catch (error) {
      throw new TACCryptoError(`Invalid key data: ${error.message}`, TACErrorCodes.INVALID_KEY_DATA);
    }

    // Verify it's a supported key type
    const supportedTypes = ['rsa', 'rsa-pss'];
    if (!supportedTypes.includes(this.privateKey.asymmetricKeyType)) {
      throw new TACCryptoError(
        'TAC Protocol requires RSA keys (minimum 2048-bit, 3072-bit recommended)',
        TACErrorCodes.UNSUPPORTED_KEY_TYPE
      );
    }

    // Verify minimum key size (2048 bits = 256 bytes)
    const keySizeBytes = this.privateKey.asymmetricKeyDetails?.modulusLength;
    if (keySizeBytes && keySizeBytes < 2048) {
      throw new TACCryptoError(
        `RSA key size ${keySizeBytes} bits is too small. Minimum 2048 bits required (3072-bit recommended)`,
        TACErrorCodes.KEY_SIZE_TOO_SMALL
      );
    }

    // Always derive public key from private key
    this.publicKey = crypto.createPublicKey(this.privateKey);

    // Store key type and algorithm
    this.keyType = getKeyType(this.privateKey);
    this.signingAlgorithm = getAlgorithmForKey(this.privateKey, 'sig');
  }

  /**
   * Generate key ID from public key
   * @returns {string} Base64url encoded SHA-256 hash of public key
   * @throws {Error} If no public key is available
   */
  generateKeyId() {
    if (!this.publicKey) {
      throw new TACValidationError('No public key available. Load or set keys first.', TACErrorCodes.NO_PUBLIC_KEY);
    }
    const keyData = this.publicKey.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(keyData).digest('base64url');
  }

  /**
   * Fetch JWKS from a domain's well-known endpoint
   * @param {string} domain - Domain to fetch JWKS from
   * @param {boolean} forceRefresh - Force cache bypass
   * @returns {Promise<Array>} Array of JWK objects
   */
  async fetchJWKS(domain, forceRefresh = false) {
    return await fetchJWKSWithRetry(domain, {
      cache: this.jwksCache,
      maxRetries: this.maxRetries,
      retryDelay: this.retryDelay,
      maxDelay: this.retryDelay * 30,
      userAgent: getUserAgent({ hideVersion: this.hideUserAgentVersion }),
      forceRefresh
    });
  }

  /**
   * Add data for a specific recipient domain
   * Data will be encrypted when generateTACMessage is called
   * @param {string} domain - Recipient domain
   * @param {Object} data - Data to encrypt for this recipient
   */
  async addRecipientData(domain, data) {
    // Store the data - encryption happens later in generateTACMessage
    this.recipientData[domain] = data;
  }

  /**
   * Set recipients data (clears existing data first)
   * @param {Object} recipientsData - Object mapping domains to their data
   *   Example: { 'merchant.com': { order: '123' }, 'vendor.com': { shipment: 'abc' } }
   */
  async setRecipientsData(recipientsData) {
    this.recipientData = { ...recipientsData };
  }

  /**
   * Clear all recipient data
   */
  clearRecipientData() {
    this.recipientData = {};
  }

  /**
   * Generate TAC-Protocol message with signed JWT and encrypted data
   * @returns {Promise<string>} Base64-encoded TAC-Protocol message (ready for HTTP headers or body)
   * @throws {Error} If no private key is available or encryption fails
   */
  async generateTACMessage() {
    if (!this.privateKey) {
      throw new TACValidationError('No private key available. Load or set keys first.', TACErrorCodes.NO_PRIVATE_KEY);
    }

    if (Object.keys(this.recipientData).length === 0) {
      throw new TACValidationError(
        'No recipient data added. Use addRecipientData() first.',
        TACErrorCodes.NO_RECIPIENT_DATA
      );
    }

    // Prepare recipient public keys map
    const recipientPublicKeys = {};
    const fetchPromises = [];

    // Fetch all recipient public keys in parallel
    for (const domain of Object.keys(this.recipientData)) {
      fetchPromises.push(
        this.fetchJWKS(domain)
          .then(jwks => {
            const encryptionKey = findEncryptionKey(jwks);
            if (!encryptionKey) {
              throw new TACNetworkError(
                `No suitable encryption key found for ${domain}`,
                TACErrorCodes.NO_ENCRYPTION_KEY_FOUND
              );
            }
            recipientPublicKeys[domain] = encryptionKey;
          })
          .catch(error => {
            throw new TACNetworkError(
              `Failed to fetch keys for ${domain}: ${error.message}`,
              TACErrorCodes.JWKS_FETCH_FAILED
            );
          })
      );
    }

    await Promise.all(fetchPromises);

    // Create individual JWE for each recipient with their specific data
    const now = Math.floor(Date.now() / 1000);
    const recipientJWEs = [];

    for (const [domain, jwk] of Object.entries(recipientPublicKeys)) {
      // Generate unique JWT ID to prevent replay attacks
      const jti = crypto.randomUUID();

      // Create JWT payload with only this recipient's data
      const payload = {
        iss: this.domain,
        exp: now + this.ttl,
        iat: now,
        aud: domain, // Audience claim for this specific recipient
        jti: jti, // Unique JWT ID to prevent replay attacks
        data: this.recipientData[domain] // Only this recipient's data
      };

      // Step 1: Create and SIGN the JWT with sender's private key (JWS)
      const keyId = await this.generateKeyId();
      let signedJWT;
      try {
        signedJWT = await new jose.SignJWT(payload)
          .setProtectedHeader({ alg: this.signingAlgorithm, typ: 'JWT', kid: keyId })
          .setIssuer(this.domain)
          .setAudience(domain)
          .setIssuedAt(now)
          .setExpirationTime(now + this.ttl)
          .setJti(jti)
          .sign(this.privateKey); // Sign with sender's private key for authentication
      } catch (error) {
        throw new TACCryptoError(`JWT signing failed: ${error.message}`, TACErrorCodes.JWT_SIGNING_FAILED);
      }

      // Step 2: ENCRYPT the signed JWT with recipient's public key (JWE)
      let publicKey;
      try {
        publicKey = await jose.importJWK(jwk);
      } catch (error) {
        throw new TACCryptoError(
          `Failed to import JWK for ${domain}: ${error.message}`,
          TACErrorCodes.JWK_IMPORT_FAILED
        );
      }

      const algorithm = jwk.alg || 'RSA-OAEP-256';
      let recipientJWE;
      try {
        // Use compact encryption for the signed JWT string
        recipientJWE = await new jose.CompactEncrypt(new TextEncoder().encode(signedJWT))
          .setProtectedHeader({ alg: algorithm, enc: 'A256GCM', cty: 'JWT' })
          .encrypt(publicKey);
      } catch (error) {
        throw new TACCryptoError(`Encryption failed for ${domain}: ${error.message}`, TACErrorCodes.ENCRYPTION_FAILED);
      }

      recipientJWEs.push({
        recipient: domain,
        jwe: recipientJWE
      });
    }

    // Create multi-recipient container
    const multiRecipientMessage = {
      version: SCHEMA_VERSION,
      recipients: recipientJWEs.map(r => ({
        kid: r.recipient,
        jwe: r.jwe
      }))
    };

    const messageJson = JSON.stringify(multiRecipientMessage);
    return Buffer.from(messageJson).toString('base64');
  }

  /**
   * Get public key as JWK for publishing (bidirectional use)
   * @returns {Promise<Object>} JWK representation of the public key
   * @throws {Error} If no public key is available
   */
  async getPublicJWK() {
    return await publicKeyToJWK(this.publicKey, this.generateKeyId());
  }

  /**
   * Clear JWKS cache
   * @param {string} domain - Specific domain to clear, or null for all
   */
  clearCache(domain = null) {
    this.jwksCache.clear(domain);
  }
}

export default TACSender;
