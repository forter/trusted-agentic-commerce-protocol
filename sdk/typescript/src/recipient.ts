import crypto, { KeyObject } from "node:crypto";
import * as jose from "jose";
import { JWKSCache, fetchJWKSWithRetry, findSigningKey, publicKeyToJWK, getUserAgent, JWK } from "./utils.js";
import { TACValidationError, TACCryptoError, TACNetworkError, TACMessageError, TACErrorCodes } from "./errors.js";
// import { Recipient } from "../../../schema/2025-08-27/schema.js";
type Recipient = Record<string, any>; // Temporary fallback

export interface RecipientOptions {
  domain: string;
  privateKey: KeyObject | string;
  cacheTimeout?: number;
  maxRetries?: number;
  retryDelay?: number;
}

export interface ProcessingResult {
  valid: boolean;
  issuer: string | null;
  expires: Date | null;
  data: (Partial<Recipient> & Record<string, any>) | null;
  recipients: string[];
  errors: string[];
}

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
      throw new TACValidationError("domain is required in TACRecipient constructor", TACErrorCodes.DOMAIN_REQUIRED);
    }
    if (!options.privateKey) {
      throw new TACValidationError(
        "privateKey is required in TACRecipient constructor",
        TACErrorCodes.PRIVATE_KEY_REQUIRED
      );
    }

    this.domain = options.domain;
    this.setPrivateKey(options.privateKey); // This sets both private and public keys
    this.jwksCache = new JWKSCache(options.cacheTimeout || 3600000);
    this.maxRetries = options.maxRetries || 3;
    this.retryDelay = options.retryDelay || 1000;
  }

  /**
   * Set private key and automatically derive public key
   * @param privateKey - Private key object or PEM string (RSA or EC)
   * @private
   */
  setPrivateKey(privateKey: KeyObject | string): void {
    try {
      if (typeof privateKey === "string") {
        this.privateKey = crypto.createPrivateKey(privateKey);
      } else {
        this.privateKey = privateKey;
      }
    } catch (error) {
      throw new TACCryptoError(`Invalid key data: ${(error as Error).message}`, TACErrorCodes.INVALID_KEY_DATA);
    }

    // Verify it's a supported key type
    const supportedTypes = ["rsa", "rsa-pss", "ec"];
    if (!supportedTypes.includes(this.privateKey.asymmetricKeyType!)) {
      throw new TACCryptoError(
        "TAC Protocol requires RSA or EC (P-256/384/521) keys",
        TACErrorCodes.UNSUPPORTED_KEY_TYPE
      );
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
      throw new TACValidationError("No public key available. Load or set keys first.", TACErrorCodes.NO_PUBLIC_KEY);
    }
    const keyData = this.publicKey.export({ type: "spki", format: "der" });
    return crypto.createHash("sha256").update(keyData).digest("base64url");
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
      retryDelay: this.retryDelay,
      maxDelay: this.retryDelay * 30,
      userAgent: getUserAgent(),
      forceRefresh,
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
      result.errors.push("Missing TAC-Protocol message");
      return result;
    }

    // Decode base64 message
    let decodedMessage: string;
    try {
      // Try to decode as base64 first
      decodedMessage = Buffer.from(tacMessage, "base64").toString("utf8");
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
        throw new TACMessageError("Invalid TAC-Protocol message format", TACErrorCodes.INVALID_MESSAGE_FORMAT);
      }

      // Validate message structure
      if (!message.recipients || !Array.isArray(message.recipients)) {
        throw new TACMessageError("Invalid message format: missing recipients", TACErrorCodes.MISSING_RECIPIENTS);
      }

      result.recipients = message.recipients.map((r: any) => r.kid || "unknown");

      // Find our specific JWE
      const ourRecipient = message.recipients.find((r: any) => r.kid === this.domain);
      if (!ourRecipient) {
        throw new TACMessageError(`Not a recipient: ${this.domain}`, TACErrorCodes.NOT_A_RECIPIENT);
      }

      if (!this.privateKey) {
        throw new TACValidationError("No private key available for decryption", TACErrorCodes.NO_PRIVATE_KEY);
      }

      // Step 1: DECRYPT the JWE to get the signed JWT
      let plaintext: Uint8Array;
      try {
        ({ plaintext } = await jose.compactDecrypt(ourRecipient.jwe, this.privateKey));
      } catch (error) {
        throw new TACCryptoError(`Decryption failed: ${(error as Error).message}`, TACErrorCodes.DECRYPTION_FAILED);
      }

      // Convert decrypted bytes back to JWT string
      const signedJWT = new TextDecoder().decode(plaintext);

      // Step 2: VERIFY the JWT signature using sender's public key
      // First, get the sender's domain and key ID from the JWT (without verification)
      let unverifiedPayload: any, unverifiedHeader: any;
      try {
        unverifiedPayload = jose.decodeJwt(signedJWT);
        unverifiedHeader = jose.decodeProtectedHeader(signedJWT);
      } catch (error) {
        throw new TACCryptoError(`JWT decode failed: ${(error as Error).message}`, TACErrorCodes.JWT_DECODE_FAILED);
      }

      if (!unverifiedPayload.iss) {
        throw new TACMessageError("JWT missing issuer (iss) claim", TACErrorCodes.JWT_MISSING_ISSUER);
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
        throw new TACNetworkError("No suitable signing key found", TACErrorCodes.NO_SIGNING_KEY_FOUND);
      }

      // Import the sender's public key for JWT verification
      let senderPublicKey: jose.KeyLike | Uint8Array;
      try {
        senderPublicKey = await jose.importJWK(signingKey);
      } catch (error) {
        throw new TACCryptoError(
          `Failed to import sender JWK: ${(error as Error).message}`,
          TACErrorCodes.JWK_IMPORT_FAILED
        );
      }

      // VERIFY the JWT signature - this is the crucial security step!
      let payload: any;
      try {
        ({ payload } = await jose.jwtVerify(signedJWT, senderPublicKey, {
          issuer: agentDomain,
          audience: this.domain,
          clockTolerance: "5m", // Allow 5 minutes clock skew
        }));
      } catch (error) {
        throw new TACCryptoError(
          `Signature verification failed: ${(error as Error).message}`,
          TACErrorCodes.SIGNATURE_VERIFICATION_FAILED
        );
      }

      // Additional manual validation for iat claim (not validated by jose.jwtVerify by default)
      const now = Math.floor(Date.now() / 1000);
      const clockTolerance = 300; // 5 minutes in seconds

      if (payload.iat && payload.iat > now + clockTolerance) {
        throw new TACMessageError("JWT not yet valid (issued in the future)", TACErrorCodes.JWT_NOT_YET_VALID);
      }

      // Extract data from verified payload
      result.valid = true;
      result.issuer = payload.iss;
      result.expires = new Date(payload.exp * 1000);

      // Get data specific to this recipient
      result.data = payload.data || null;
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
        decodedMessage = Buffer.from(tacMessage, "base64").toString("utf8");
        JSON.parse(decodedMessage);
      } catch (e) {
        decodedMessage = tacMessage;
      }

      const message = JSON.parse(decodedMessage);

      return {
        version: message.version || "2025-08-27",
        recipients: message.recipients ? message.recipients.map((r: any) => r.kid || "unknown") : [],
      };
    } catch (error) {
      return {
        error: "Invalid TAC-Protocol message format",
        recipients: [],
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
