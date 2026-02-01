import crypto from 'node:crypto';
import * as jose from 'jose';
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findSigningKey,
  getKeyType,
  getAlgorithmForKey,
  publicKeyToJWK
} from './utils.js';
import { getUserAgent } from './utils.js';
import { TACValidationError, TACCryptoError, TACNetworkError, TACMessageError, TACErrorCodes } from './errors.js';

/**
 * TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
 * Handles TAC-Protocol message verification and decryption
 */
class TACRecipient {
  /**
   * @param {Object} options - Configuration options
   * @param {string} options.domain - Domain of the recipient (required)
   * @param {crypto.KeyObject|string} options.privateKey - Private key for decryption (required)
   * @param {number} options.cacheTimeout - JWKS cache timeout in ms (default: 3600000)
   * @param {number} options.maxRetries - Max retry attempts for network requests (default: 3)
   * @param {number} options.retryDelay - Retry delay in ms (default: 1000)
   * @param {number} options.clockTolerance - Clock skew tolerance in seconds (default: 300 = 5 minutes)
   * @param {boolean} options.hideUserAgentVersion - If true, omit version details from User-Agent header (default: false)
   */
  constructor(options = {}) {
    if (!options.domain) {
      throw new TACValidationError('domain is required in TACRecipient constructor', TACErrorCodes.DOMAIN_REQUIRED);
    }
    if (!options.privateKey) {
      throw new TACValidationError(
        'privateKey is required in TACRecipient constructor',
        TACErrorCodes.PRIVATE_KEY_REQUIRED
      );
    }

    this.domain = options.domain;
    this.setPrivateKey(options.privateKey); // This sets both private and public keys
    this.jwksCache = new JWKSCache(options.cacheTimeout || 3600000);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.clockTolerance = options.clockTolerance !== undefined ? options.clockTolerance : 300; // 5 minutes default
    this.hideUserAgentVersion = options.hideUserAgentVersion || false;
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

    // Always derive public key from private key
    this.publicKey = crypto.createPublicKey(this.privateKey);

    // Store key type and algorithm
    this.keyType = getKeyType(this.privateKey);
    this.encryptionAlgorithm = getAlgorithmForKey(this.privateKey, 'enc');
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
   * Process TAC-Protocol message
   * @param {string} tacMessage - Base64-encoded TAC-Protocol message (from header or body)
   * @returns {Promise<Object>} Processing result with valid, issuer, expires, data, recipients, errors
   */
  async processTACMessage(tacMessage) {
    const result = {
      valid: false,
      issuer: null,
      expires: null,
      jti: null, // JWT ID for replay detection
      data: null,
      recipients: [],
      errors: []
    };

    if (!tacMessage) {
      result.errors.push('Missing TAC-Protocol message');
      return result;
    }

    // Decode base64 message (strictly required - raw JSON not accepted)
    let decodedMessage;

    // Check message size limit (100KB max to prevent DoS)
    const MAX_MESSAGE_SIZE = 100 * 1024; // 100KB
    if (tacMessage.length > MAX_MESSAGE_SIZE) {
      result.errors.push(`Message too large: ${tacMessage.length} bytes exceeds maximum of ${MAX_MESSAGE_SIZE} bytes`);
      return result;
    }

    // Check if input looks like raw JSON (not base64 encoded)
    const trimmed = tacMessage.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      result.errors.push('Invalid TAC-Protocol message: must be base64-encoded (raw JSON not accepted)');
      return result;
    }

    // Validate base64 format
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(tacMessage)) {
      result.errors.push('Invalid TAC-Protocol message: must be base64-encoded');
      return result;
    }

    try {
      decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
    } catch (e) {
      result.errors.push('Invalid TAC-Protocol message: must be base64-encoded');
      return result;
    }

    try {
      // Parse the multi-recipient message
      let message;
      try {
        message = JSON.parse(decodedMessage);
      } catch (e) {
        throw new TACMessageError('Invalid TAC-Protocol message format', TACErrorCodes.INVALID_MESSAGE_FORMAT);
      }

      // Validate message structure
      if (!message.recipients || !Array.isArray(message.recipients)) {
        throw new TACMessageError('Invalid message format: missing recipients', TACErrorCodes.MISSING_RECIPIENTS);
      }

      result.recipients = message.recipients.map(r => r.kid || 'unknown');

      // Find our specific JWE
      const ourRecipient = message.recipients.find(r => r.kid === this.domain);
      if (!ourRecipient) {
        throw new TACMessageError(`Not a recipient: ${this.domain}`, TACErrorCodes.NOT_A_RECIPIENT);
      }

      if (!this.privateKey) {
        throw new TACValidationError('No private key available for decryption', TACErrorCodes.NO_PRIVATE_KEY);
      }

      // Step 1: DECRYPT the JWE to get the signed JWT
      let plaintext;
      try {
        ({ plaintext } = await jose.compactDecrypt(ourRecipient.jwe, this.privateKey));
      } catch (error) {
        throw new TACCryptoError(`Decryption failed: ${error.message}`, TACErrorCodes.DECRYPTION_FAILED);
      }

      // Convert decrypted bytes back to JWT string
      const signedJWT = new TextDecoder().decode(plaintext);

      // Step 2: VERIFY the JWT signature using sender's public key
      // First, get the sender's domain and key ID from the JWT (without verification)
      let unverifiedPayload, unverifiedHeader;
      try {
        unverifiedPayload = jose.decodeJwt(signedJWT);
        unverifiedHeader = jose.decodeProtectedHeader(signedJWT);
      } catch (error) {
        throw new TACCryptoError(`JWT decode failed: ${error.message}`, TACErrorCodes.JWT_DECODE_FAILED);
      }

      if (!unverifiedPayload.iss) {
        throw new TACMessageError('JWT missing issuer (iss) claim', TACErrorCodes.JWT_MISSING_ISSUER);
      }

      if (unverifiedPayload.aud !== this.domain) {
        throw new TACMessageError(
          `JWT audience mismatch: expected ${this.domain}, got ${unverifiedPayload.aud}`,
          TACErrorCodes.JWT_AUDIENCE_MISMATCH
        );
      }

      // Step 3: Fetch sender's public key and VERIFY the JWT signature
      const agentDomain = unverifiedPayload.iss;
      const keyId = unverifiedHeader.kid; // Extract key ID for key selection
      const jwks = await this.fetchJWKS(agentDomain);

      if (!jwks || jwks.length === 0) {
        throw new TACNetworkError(`No public keys found for agent ${agentDomain}`, TACErrorCodes.NO_PUBLIC_KEYS_FOUND);
      }

      // Find appropriate signing key to verify the JWT signature (using key ID if available)
      const signingKey = findSigningKey(jwks, keyId);
      if (!signingKey) {
        throw new TACNetworkError('No suitable signing key found', TACErrorCodes.NO_SIGNING_KEY_FOUND);
      }

      // Import the sender's public key for JWT verification
      let senderPublicKey;
      try {
        senderPublicKey = await jose.importJWK(signingKey);
      } catch (error) {
        throw new TACCryptoError(`Failed to import sender JWK: ${error.message}`, TACErrorCodes.JWK_IMPORT_FAILED);
      }

      // VERIFY the JWT signature - this is the crucial security step!
      let payload;
      try {
        ({ payload } = await jose.jwtVerify(signedJWT, senderPublicKey, {
          issuer: agentDomain,
          audience: this.domain,
          clockTolerance: this.clockTolerance // Configurable clock skew tolerance
        }));
      } catch (error) {
        throw new TACCryptoError(
          `Signature verification failed: ${error.message}`,
          TACErrorCodes.SIGNATURE_VERIFICATION_FAILED
        );
      }

      // Additional manual validation for iat claim (not validated by jose.jwtVerify by default)
      const now = Math.floor(Date.now() / 1000);

      if (payload.iat && payload.iat > now + this.clockTolerance) {
        throw new TACMessageError('JWT not yet valid (issued in the future)', TACErrorCodes.JWT_NOT_YET_VALID);
      }

      // Extract data from verified payload
      result.valid = true;
      result.issuer = payload.iss;
      result.expires = new Date(payload.exp * 1000);
      result.jti = payload.jti || null; // JWT ID for replay detection

      // Get data specific to this recipient
      result.data = payload.data || null;
    } catch (error) {
      result.errors.push(error.message);
    }

    return result;
  }

  /**
   * Static method to inspect TAC-Protocol message without decryption
   * @param {string} tacMessage - Base64-encoded TAC-Protocol message
   * @returns {Object} Basic information about the message
   */
  static inspect(tacMessage) {
    try {
      // Check if input looks like raw JSON (not base64 encoded)
      const trimmed = tacMessage.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        return {
          error: 'Invalid TAC-Protocol message: must be base64-encoded (raw JSON not accepted)',
          recipients: []
        };
      }

      // Validate base64 format
      const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
      if (!base64Regex.test(tacMessage)) {
        return {
          error: 'Invalid TAC-Protocol message: must be base64-encoded',
          recipients: []
        };
      }

      // Decode base64 message
      const decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      const message = JSON.parse(decodedMessage);

      return {
        version: message.version || '2025-08-27',
        recipients: message.recipients ? message.recipients.map(r => r.kid || 'unknown') : [],
        expires: null // Cannot determine without decryption
      };
    } catch (error) {
      return {
        error: 'Invalid TAC-Protocol message format',
        recipients: []
      };
    }
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

export default TACRecipient;
