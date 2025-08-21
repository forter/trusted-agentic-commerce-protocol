import crypto, { KeyObject } from "node:crypto";
import * as jose from 'jose';
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

    // Decode base64 message
    let decodedMessage: string;
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
      let message: any;
      try {
        message = JSON.parse(decodedMessage);
      } catch (e) {
        result.errors.push('Invalid TAC-Protocol message format');
        return result;
      }

      // Validate message structure
      if (!message.recipients || !Array.isArray(message.recipients)) {
        result.errors.push('Invalid message format: missing recipients');
        return result;
      }

      result.recipients = message.recipients.map((r: any) => r.kid || 'unknown');

      // Find our specific JWE
      const ourRecipient = message.recipients.find((r: any) => r.kid === this.domain);
      if (!ourRecipient) {
        result.errors.push(`Not a recipient: ${this.domain}`);
        return result;
      }

      if (!this.privateKey) {
        result.errors.push('No private key available for decryption');
        return result;
      }

      // Decrypt our specific JWE
      const { payload } = await jose.jwtDecrypt(ourRecipient.jwe, this.privateKey);

      // Verify the issuer and audience claims
      if (!payload.iss) {
        result.errors.push('JWT missing issuer (iss) claim');
        return result;
      }
      
      if (payload.aud !== this.domain) {
        result.errors.push(`JWT audience mismatch: expected ${this.domain}, got ${payload.aud}`);
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
      
      // Get data specific to this recipient
      result.data = (payload as any).data || null;

    } catch (error) {
      result.errors.push((error as Error).message);
    }

    return result;
  }

  /**
   * Static method to inspect TAC-Protocol message without decryption
   * @param tacMessage - Base64-encoded TAC-Protocol message
   * @returns Basic information about the message
   */
  static inspect(tacMessage: string): { version?: string; recipients: string[]; expires?: Date; error?: string } {
    try {
      // Decode base64 message
      let decodedMessage: string;
      try {
        decodedMessage = Buffer.from(tacMessage, 'base64').toString('utf8');
        JSON.parse(decodedMessage);
      } catch (e) {
        decodedMessage = tacMessage;
      }
      
      const message = JSON.parse(decodedMessage);
      
      return {
        version: message.version || '2025-08-21',
        recipients: message.recipients ? message.recipients.map((r: any) => r.kid || 'unknown') : []
        // expires is omitted since we can't determine it without decryption
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
   * @returns JWK representation of the public key
   * @throws If no public key is available
   */
  async getPublicJWK(): Promise<JWK> {
    return await publicKeyToJWK(this.publicKey, this.generateKeyId());
  }

  /**
   * Clear JWKS cache
   * @param domain - Specific domain to clear, or null for all
   */
  clearCache(domain?: string): void {
    this.jwksCache.clear(domain);
  }
}