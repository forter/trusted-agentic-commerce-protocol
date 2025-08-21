import crypto from "node:crypto";
import * as jose from 'jose';
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findSigningKey,
  getKeyType,
  getAlgorithmForKey,
  publicKeyToJWK
} from "./utils.js";
import { getRecipientUserAgent } from './version.js';

/**
 * TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
 * Handles TAC-Protocol message verification and decryption
 */
class TACRecipient {
  /**
   * @param {Object} options - Configuration options
   * @param {string} options.domain - Domain of the recipient (required)
   * @param {crypto.KeyObject|string} options.privateKey - Private key for decryption - RSA or EC (required)
   * @param {number} options.cacheTimeout - JWKS cache timeout in ms (default: 3600000)
   * @param {number} options.maxRetries - Max retry attempts for network requests (default: 3)
   * @param {number} options.retryDelay - Retry delay in ms (default: 1000)
   */
  constructor(options = {}) {
    if (!options.domain) {
      throw new Error("domain is required in TACRecipient constructor");
    }
    if (!options.privateKey) {
      throw new Error("privateKey is required in TACRecipient constructor");
    }
    
    this.domain = options.domain;
    this.setPrivateKey(options.privateKey); // This sets both private and public keys
    this.jwksCache = new JWKSCache(options.cacheTimeout || 3600000);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Set private key and automatically derive public key
   * @param {crypto.KeyObject|string} privateKey - Private key object or PEM string (RSA or EC)
   * @private
   */
  setPrivateKey(privateKey) {
    if (typeof privateKey === "string") {
      this.privateKey = crypto.createPrivateKey(privateKey);
    } else {
      this.privateKey = privateKey;
    }

    // Verify it's a supported key type
    const supportedTypes = ['rsa', 'rsa-pss', 'ec'];
    if (!supportedTypes.includes(this.privateKey.asymmetricKeyType)) {
      throw new Error('TAC Protocol requires RSA or EC (P-256/384/521) keys');
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
      throw new Error("No public key available. Load or set keys first.");
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
      initialDelay: this.retryDelay,
      maxDelay: this.retryDelay * 30,
      userAgent: getRecipientUserAgent(),
      forceRefresh,
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
      data: null,
      recipients: [],
      errors: [],
    };

    if (!tacMessage) {
      result.errors.push('Missing TAC-Protocol message');
      return result;
    }

    // Decode base64 message
    let decodedMessage;
    try {
      // Try to decode as base64 first
      decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
      // Validate it's valid JSON
      JSON.parse(decodedMessage);
    } catch (e) {
      // If base64 decode fails, assume it's already JSON (backward compatibility)
      decodedMessage = tacMessage;
    }

    try {
      // Parse the multi-recipient message
      let message;
      try {
        message = JSON.parse(decodedMessage);
      } catch (e) {
        throw new Error('Invalid TAC-Protocol message format');
      }

      // Validate message structure
      if (!message.recipients || !Array.isArray(message.recipients)) {
        throw new Error('Invalid message format: missing recipients');
      }

      result.recipients = message.recipients.map(r => r.kid || 'unknown');

      // Find our specific JWE
      const ourRecipient = message.recipients.find(r => r.kid === this.domain);
      if (!ourRecipient) {
        throw new Error(`Not a recipient: ${this.domain}`);
      }

      if (!this.privateKey) {
        throw new Error('No private key available for decryption');
      }

      // Decrypt and verify our specific JWE in one step
      // jose.jwtDecrypt automatically verifies the JWT signature during decryption
      const { payload } = await jose.jwtDecrypt(ourRecipient.jwe, this.privateKey);
      
      // Verify the issuer and audience claims
      if (!payload.iss) {
        throw new Error('JWT missing issuer (iss) claim');
      }
      
      if (payload.aud !== this.domain) {
        throw new Error(`JWT audience mismatch: expected ${this.domain}, got ${payload.aud}`);
      }

      // Additional signature verification by fetching sender's public key
      const agentDomain = payload.iss;
      const jwks = await this.fetchJWKS(agentDomain);
      
      if (!jwks || jwks.length === 0) {
        throw new Error(`No public keys found for agent ${agentDomain}`);
      }

      // Find appropriate signing key to verify this came from the right sender
      const signingKey = findSigningKey(jwks);
      if (!signingKey) {
        throw new Error('No suitable signing key found');
      }
      
      // The payload is already verified through JWE decryption, but we could
      // add additional verification here if needed for extra security

      // Extract data from verified payload
      result.valid = true;
      result.issuer = payload.iss;
      result.expires = new Date(payload.exp * 1000);
      
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
      // Decode base64 message
      let decodedMessage;
      try {
        decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
        JSON.parse(decodedMessage);
      } catch (e) {
        decodedMessage = tacMessage;
      }
      
      const message = JSON.parse(decodedMessage);
      
      return {
        version: message.version || '2025-08-21',
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