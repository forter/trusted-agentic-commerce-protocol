import crypto from "node:crypto";
import * as jose from "jose";
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findEncryptionKey,
  getKeyType,
  getAlgorithmForKey,
  publicKeyToJWK,
} from "./utils.js";
import { getSenderUserAgent } from "./version.js";

/**
 * TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
 * Creates JWT with issuer and expiration, encrypts data for multiple recipients
 */
class TACSender {
  /**
   * @param {Object} options - Configuration options
   * @param {string} options.domain - Domain of the agent (required, used as 'iss' in JWT)
   * @param {crypto.KeyObject|string} options.privateKey - Private key for signing - RSA or EC (required)
   * @param {number} options.ttl - JWT expiry time in seconds (default: 3600)
   * @param {number} options.cacheTimeout - JWKS cache timeout in ms (default: 3600000)
   * @param {number} options.maxRetries - Max retry attempts for network requests (default: 3)
   * @param {number} options.retryDelay - Retry delay in ms (default: 1000)
   */
  constructor(options = {}) {
    if (!options.domain) {
      throw new Error("domain is required in TACSender constructor");
    }
    if (!options.privateKey) {
      throw new Error("privateKey is required in TACSender constructor");
    }

    this.domain = options.domain;
    this.setPrivateKey(options.privateKey); // This sets both private and public keys
    this.ttl = options.ttl || 3600; // 1 hour default
    this.jwksCache = new JWKSCache(options.cacheTimeout || 3600000);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
    this.recipientData = {}; // Store recipient data for later encryption
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
    const supportedTypes = ["rsa", "rsa-pss", "ec"];
    if (!supportedTypes.includes(this.privateKey.asymmetricKeyType)) {
      throw new Error("TAC Protocol requires RSA or EC (P-256/384/521) keys");
    }

    // Always derive public key from private key
    this.publicKey = crypto.createPublicKey(this.privateKey);

    // Store key type and algorithm
    this.keyType = getKeyType(this.privateKey);
    this.signingAlgorithm = getAlgorithmForKey(this.privateKey, "sig");
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
    const keyData = this.publicKey.export({ type: "spki", format: "der" });
    return crypto.createHash("sha256").update(keyData).digest("base64url");
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
      userAgent: getSenderUserAgent(),
      forceRefresh,
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
      throw new Error("No private key available. Load or set keys first.");
    }

    if (Object.keys(this.recipientData).length === 0) {
      throw new Error("No recipient data added. Use addRecipientData() first.");
    }

    // Prepare recipient public keys map
    const recipientPublicKeys = {};
    const fetchPromises = [];

    // Fetch all recipient public keys in parallel
    for (const domain of Object.keys(this.recipientData)) {
      fetchPromises.push(
        this.fetchJWKS(domain)
          .then((jwks) => {
            const encryptionKey = findEncryptionKey(jwks);
            if (!encryptionKey) {
              throw new Error(`No suitable encryption key found for ${domain}`);
            }
            recipientPublicKeys[domain] = encryptionKey;
          })
          .catch((error) => {
            throw new Error(
              `Failed to fetch keys for ${domain}: ${error.message}`
            );
          })
      );
    }

    await Promise.all(fetchPromises);

    // Create individual JWE for each recipient with their specific data
    const now = Math.floor(Date.now() / 1000);
    const recipientJWEs = [];

    for (const [domain, jwk] of Object.entries(recipientPublicKeys)) {
      // Create JWT payload with only this recipient's data
      const payload = {
        iss: this.domain,
        exp: now + this.ttl,
        iat: now,
        aud: domain, // Audience claim for this specific recipient
        data: this.recipientData[domain], // Only this recipient's data
      };

      // Sign the JWT using appropriate algorithm based on key type
      const jws = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: this.signingAlgorithm })
        .sign(this.privateKey);

      // Encrypt the signed JWT for this specific recipient
      const publicKey = await jose.importJWK(jwk);
      const algorithm = jwk.alg || "RSA-OAEP-256";

      const recipientJWE = await new jose.EncryptJWT(payload)
        .setProtectedHeader({ alg: algorithm, enc: "A256GCM" })
        .setIssuedAt()
        .setExpirationTime(now + this.ttl)
        .setAudience(domain)
        .encrypt(publicKey);

      recipientJWEs.push({
        recipient: domain,
        jwe: recipientJWE,
      });
    }

    // Create multi-recipient container
    const multiRecipientMessage = {
      version: "2025-08-27",
      recipients: recipientJWEs.map((r) => ({
        kid: r.recipient,
        jwe: r.jwe,
      })),
    };

    const messageJson = JSON.stringify(multiRecipientMessage);
    return Buffer.from(messageJson).toString("base64");
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
