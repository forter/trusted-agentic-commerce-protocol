import crypto, { KeyObject } from 'node:crypto';
import * as jose from 'jose';
import {
  JWKSCache,
  fetchJWKSWithRetry,
  findEncryptionKey,
  generateKeyId,
  isRSAKey,
  publicKeyToJWK
} from './utils.js';
import { 
  SenderOptions, 
  JWK, 
  Recipient, 
  Recipients
} from './sdk-types.js';
import { getSenderUserAgent } from './version.js';

/**
 * TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
 * Handles JWT signing and multi-recipient JWE encryption
 */
export default class TACSender {
  public readonly domain: string;
  private privateKey!: KeyObject;
  private publicKey!: KeyObject;
  private readonly ttl: number;
  private readonly jwksCache: JWKSCache;
  private readonly maxRetries: number;
  private readonly retryDelay: number;
  private recipientData: Recipients = {};

  /**
   * @param options - Configuration options
   */
  constructor(options: SenderOptions) {
    if (!options.domain) {
      throw new Error('domain is required in TACSender constructor');
    }
    if (!options.privateKey) {
      throw new Error('privateKey is required in TACSender constructor');
    }
    
    this.domain = options.domain;
    this.setPrivateKey(options.privateKey);
    this.ttl = options.ttl || 3600;
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
      throw new Error('No public key available. Load or set keys first.');
    }
    return generateKeyId(this.publicKey);
  }

  /**
   * Add data to be encrypted for a specific recipient
   * @param domain - Recipient domain
   * @param data - Data to encrypt for this recipient
   */
  addRecipientData(domain: string, data: Recipient): void {
    this.recipientData[domain] = data;
  }

  /**
   * Set all recipients data, clearing any existing data first
   * @param recipientData - Dictionary mapping domain to data
   */
  setRecipientsData(recipientData: Recipients): void {
    this.recipientData = { ...recipientData };
  }

  /**
   * Clear all recipient data
   */
  clearRecipientData(): void {
    this.recipientData = {};
  }

  /**
   * Generate TAC-Protocol message with signed JWT and encrypted data
   * @returns Base64-encoded TAC-Protocol message (ready for HTTP headers or body)
   */
  async generateTACMessage(): Promise<string> {
    if (Object.keys(this.recipientData).length === 0) {
      throw new Error('No recipient data added. Use addRecipientData() first.');
    }

    if (!this.privateKey) {
      throw new Error('No private key available for signing');
    }

    // Fetch recipient public keys
    const recipientPublicKeys: Record<string, JWK> = {};
    for (const domain of Object.keys(this.recipientData)) {
      const keys = await this.fetchJWKS(domain);
      const encryptionKey = findEncryptionKey(keys);
      if (!encryptionKey) {
        throw new Error(`No encryption key found for ${domain}`);
      }
      recipientPublicKeys[domain] = encryptionKey;
    }

    // Create individual JWE for each recipient with their specific data
    const now = Math.floor(Date.now() / 1000);
    const recipientJWEs: Array<{ kid: string; jwe: string }> = [];

    for (const [domain, jwk] of Object.entries(recipientPublicKeys)) {
      // Create JWT payload with only this recipient's data
      const payload = {
        iss: this.domain,
        exp: now + this.ttl,
        iat: now,
        aud: domain,  // Audience claim for this specific recipient
        data: this.recipientData[domain]  // Only this recipient's data
      };

      // Encrypt the signed JWT for this specific recipient
      const publicKey = await jose.importJWK(jwk);
      const algorithm = jwk.alg || 'RSA-OAEP-256';
      
      const recipientJWE = await new jose.EncryptJWT(payload)
        .setProtectedHeader({ alg: algorithm, enc: 'A256GCM' })
        .setIssuedAt()
        .setExpirationTime(now + this.ttl)
        .setAudience(domain)
        .encrypt(publicKey);

      recipientJWEs.push({
        kid: domain,
        jwe: recipientJWE
      });
    }

    // Create multi-recipient container
    const multiRecipientMessage = {
      version: '2025-08-21',
      recipients: recipientJWEs
    };

    const messageJson = JSON.stringify(multiRecipientMessage);
    return Buffer.from(messageJson).toString('base64');
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
      userAgent: getSenderUserAgent(),
      forceRefresh
    });
  }

  /**
   * Clear JWKS cache
   * @param domain - Specific domain to clear, or null for all
   */
  clearCache(domain?: string): void {
    this.jwksCache.clear(domain);
  }

  /**
   * Get public key as JWK for publishing (bidirectional use)
   * @returns JWK representation of the public key
   * @throws If no public key is available
   */
  async getPublicJWK(): Promise<JWK> {
    return await publicKeyToJWK(this.publicKey, this.generateKeyId());
  }
}