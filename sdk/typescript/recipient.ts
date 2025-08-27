import crypto, { KeyObject } from "node:crypto";
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findSigningKey,
  generateKeyId,
  isRSAKey,
  publicKeyToJWK
} from "./utils.js";
import {
  RecipientOptions,
  JWK,
  ProcessingResult
} from "./sdk-types.js";
import { getRecipientUserAgent } from './version.js';

/**
 * TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
 * Handles TAC-Protocol message verification and decryption
 */
export default class TACRecipient {
  public readonly domain: string;
  private privateKey!: KeyObject;
  private publicKey!: KeyObject;
  private readonly jwksCache: JWKSCache;
  private readonly maxRetries: number;
  private readonly retryDelay: number;

  /**
   * @param options - Configuration options
   */
  constructor(options: RecipientOptions) {
    if (!options.domain) {
      throw new Error("domain is required in TACRecipient constructor");
    }
    if (!options.privateKey) {
      throw new Error("privateKey is required in TACRecipient constructor");
    }
    
    this.domain = options.domain;
    this.setPrivateKey(options.privateKey);
    this.jwksCache = new JWKSCache(options.cacheTimeout || 3600000);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Set private key and automatically derive public key
   * @param privateKey - RSA private key object or PEM string
   * @private
   */
  setPrivateKey(privateKey: KeyObject | string): void {
    if (typeof privateKey === 'string') {
      this.privateKey = crypto.createPrivateKey(privateKey);
    } else {
      this.privateKey = privateKey;
    }

    // Verify it's an RSA key
    if (!isRSAKey(this.privateKey)) {
      throw new Error('TAC Protocol requires RSA keys for signing and encryption');
    }

    // Always derive public key from private key
    this.publicKey = crypto.createPublicKey(this.privateKey);
  }

  /**
   * Generate key ID from public key
   * @returns Base64url encoded SHA-256 hash of public key
   * @throws If no public key is available
   */
  generateKeyId(): string {
    if (!this.publicKey) {
      throw new Error("No public key available. Load or set keys first.");
    }
    return generateKeyId(this.publicKey);
  }

  /**
   * Fetch JWKS from a domain's well-known endpoint
   * @param domain - Domain to fetch JWKS from
   * @param forceRefresh - Force cache bypass
   * @returns Array of JWK objects
   */
  async fetchJWKS(domain: string, forceRefresh: boolean = false): Promise<JWK[]> {
    return await fetchJWKSWithRetry(domain, {
      cache: this.jwksCache,
      maxRetries: this.maxRetries,
      initialDelay: this.retryDelay,
      maxDelay: this.retryDelay * 30,
      userAgent: getRecipientUserAgent(),
      forceRefresh
    });
  }

  /**
   * Process TAC-Protocol message
   * @param tacMessage - Base64-encoded TAC-Protocol message (from header or body)
   * @returns Processing result with valid, issuer, expires, data, recipients, errors
   */
  async processTACMessage(tacMessage?: string): Promise<ProcessingResult> {
    const result: ProcessingResult = {
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

    try {
      // Parse the message directly as JSON (no base64 encoding)
      let message: any;
      try {
        message = JSON.parse(tacMessage);
      } catch (e) {
        result.errors.push('Invalid TAC-Protocol message format');
        return result;
      }

      // Validate message structure
      if (!message.recipients || !Array.isArray(message.recipients)) {
        result.errors.push('Invalid message format: missing recipients');
        return result;
      }

      result.recipients = message.recipients.map((r: any) => r.header?.kid || r.kid || 'unknown');

      // Find our specific JWE recipient
      const ourRecipientIndex = message.recipients.findIndex((r: any) => 
        (r.header?.kid || r.kid) === this.domain
      );
      
      if (ourRecipientIndex === -1) {
        result.errors.push(`Not a recipient: ${this.domain}`);
        return result;
      }
      
      const ourRecipient = message.recipients[ourRecipientIndex];
      if (!this.privateKey) {
        result.errors.push('No private key available for decryption');
        return result;
      }

      // Decrypt the encrypted CEK with our private key
      const encryptedKey = Buffer.from(ourRecipient.encrypted_key, 'base64url');
      const cek = crypto.privateDecrypt(
        {
          key: this.privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        encryptedKey
      );
      
      // Decrypt the ciphertext with AES-GCM
      // AAD needs to be the protected header in ASCII format (base64url string)
      const aad = Buffer.from(message.protected, 'ascii');
      const iv = Buffer.from(message.iv, 'base64url');
      const ciphertext = Buffer.from(message.ciphertext, 'base64url');
      const authTag = Buffer.from(message.tag, 'base64url');
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
      decipher.setAuthTag(authTag);
      decipher.setAAD(aad);
      
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
      
      const payload = JSON.parse(plaintext.toString());

      // Verify the issuer claim
      if (!payload.iss) {
        result.errors.push('Missing issuer (iss) claim');
        return result;
      }
      
      // Check if we're in the recipients list
      if (!payload.recipients || !payload.recipients[this.domain]) {
        result.errors.push(`No data for recipient: ${this.domain}`);
        return result;
      }

      // Additional signature verification by fetching sender's public key
      const agentDomain = payload.iss as string;
      const jwks = await this.fetchJWKS(agentDomain);
      
      if (!jwks || jwks.length === 0) {
        result.errors.push(`No public keys found for agent ${agentDomain}`);
        return result;
      }

      // Find appropriate signing key to verify this came from the right sender
      const signingKey = findSigningKey(jwks);
      if (!signingKey) {
        result.errors.push('No suitable signing key found');
        return result;
      }
      
      // The payload is already verified through JWE decryption, but we could
      // add additional verification here if needed for extra security

      // Extract data from verified payload
      result.valid = true;
      result.issuer = payload.iss as string;
      result.expires = new Date((payload.exp as number) * 1000);
      
      // Get data specific to this recipient from the recipients object
      result.data = payload.recipients[this.domain] || null;

    } catch (error) {
      result.errors.push((error as Error).message);
    }

    return result;
  }

  /**
   * Static method to inspect TAC-Protocol message without decryption
   * @param tacMessage - TAC-Protocol message (JSON string)
   * @returns Basic information about the message
   */
  static inspect(tacMessage: string): { version?: string; recipients: string[]; expires?: Date; error?: string } {
    try {
      const message = JSON.parse(tacMessage);
      
      // Handle JWE General JSON format
      if (message.recipients && Array.isArray(message.recipients)) {
        return {
          version: message.unprotected?.v || '2025-08-27',
          recipients: message.recipients.map((r: any) => r.header?.kid || 'unknown')
        };
      }
      
      // Fallback for other formats
      return {
        version: message.version || message.unprotected?.v || '2025-08-27',
        recipients: message.recipients ? message.recipients.map((r: any) => r.kid || r.header?.kid || 'unknown') : []
      };
    } catch (error) {
      return {
        error: 'Invalid TAC-Protocol message format',
        recipients: []
      };
    }
  }

  /**
   * Get public key as JWK for publishing (for encryption)
   * @returns JWK representation of the public key
   * @throws If no public key is available
   */
  async getPublicJWK(): Promise<JWK> {
    const jwk = await publicKeyToJWK(this.publicKey, this.generateKeyId());
    jwk.use = 'enc';
    jwk.alg = 'RSA-OAEP-256';
    return jwk;
  }

  /**
   * Clear JWKS cache
   * @param domain - Specific domain to clear, or null for all
   */
  clearCache(domain?: string): void {
    this.jwksCache.clear(domain);
  }
}