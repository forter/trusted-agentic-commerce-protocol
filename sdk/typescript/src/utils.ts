import crypto, { KeyObject } from "node:crypto";
import * as jose from "jose";
import { SCHEMA_VERSION, SDK_VERSION, SDK_LANGUAGE } from "./version.js";
import { TACNetworkError, TACCryptoError, TACErrorCodes } from "./errors.js";

// Node.js globals
/* global AbortController */

export interface JWK {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  exp?: number;
  nbf?: number;
}

export interface FetchOptions {
  cache?: JWKSCache;
  maxRetries?: number;
  retryDelay?: number;
  maxDelay?: number;
  timeout?: number;
  userAgent?: string;
  forceRefresh?: boolean;
}

export interface UserAgentOptions {
  hideVersion?: boolean;
}

/**
 * Get User-Agent string
 * @param options - Options for User-Agent generation
 * @param options.hideVersion - If true, only return "TAC-Protocol" without version details
 * @returns User-Agent string
 */
export function getUserAgent(options: UserAgentOptions = {}): string {
  if (options.hideVersion) {
    return "TAC-Protocol";
  }
  return `TAC-Protocol/${SCHEMA_VERSION} (${SDK_LANGUAGE}/${SDK_VERSION})`;
}

/**
 * JWKS cache with TTL and pending request deduplication
 */
export class JWKSCache {
  private cache = new Map<string, { keys: JWK[]; expires: number }>();
  private pendingFetches = new Map<string, Promise<JWK[]>>();

  /**
   * @param timeout - Cache timeout in milliseconds
   */
  constructor(private readonly timeout: number = 3600000) {}

  /**
   * Get cached keys if not expired
   * @param domain - Domain to get cached keys for
   * @returns Cached keys or null if expired/missing
   */
  get(domain: string): JWK[] | null {
    const cached = this.cache.get(domain);
    if (cached && cached.expires > Date.now()) {
      return cached.keys;
    }
    return null;
  }

  /**
   * Set keys in cache with expiry
   * @param domain - Domain to cache keys for
   * @param keys - JWK keys to cache
   */
  set(domain: string, keys: JWK[]): void {
    // Calculate cache expiry - use the minimum of:
    // 1. Default cache timeout
    // 2. Earliest key expiration (if any keys have exp field)
    let cacheExpires = Date.now() + this.timeout;

    // Check if any keys have exp field and adjust cache expiry
    const keyExpirations = keys.filter((k) => k.exp).map((k) => k.exp! * 1000); // Convert to milliseconds

    if (keyExpirations.length > 0) {
      const earliestExpiry = Math.min(...keyExpirations);
      cacheExpires = Math.min(cacheExpires, earliestExpiry);
    }

    this.cache.set(domain, {
      keys,
      expires: cacheExpires,
    });
  }

  /**
   * Clear cache for specific domain or all
   * @param domain - Domain to clear, or null for all
   */
  clear(domain?: string): void {
    if (domain) {
      this.cache.delete(domain);
      this.pendingFetches.delete(domain);
    } else {
      this.cache.clear();
      this.pendingFetches.clear();
    }
  }

  /**
   * Get pending fetch promise for deduplication
   * @param domain - Domain to get pending fetch for
   * @returns Pending fetch promise
   */
  getPendingFetch(domain: string): Promise<JWK[]> | undefined {
    return this.pendingFetches.get(domain);
  }

  /**
   * Store pending fetch promise
   * @param domain - Domain of pending fetch
   * @param promise - Fetch promise
   */
  setPendingFetch(domain: string, promise: Promise<JWK[]>): void {
    this.pendingFetches.set(domain, promise);
  }

  /**
   * Remove pending fetch
   * @param domain - Domain to remove pending fetch for
   */
  deletePendingFetch(domain: string): void {
    this.pendingFetches.delete(domain);
  }
}

/**
 * Fetch JWKS with exponential backoff retry and deduplication
 * @param domain - Domain to fetch JWKS from
 * @param options - Fetch options
 * @returns Array of JWK objects
 */
export async function fetchJWKSWithRetry(domain: string, options: FetchOptions = {}): Promise<JWK[]> {
  const {
    cache = null,
    maxRetries = 3,
    retryDelay = 1000,
    maxDelay = 30000,
    timeout = 10000,
    userAgent = getUserAgent(),
    forceRefresh = false,
  } = options;

  if (cache && !forceRefresh) {
    const cached = cache.get(domain);
    if (cached) {
      return cached;
    }

    const pending = cache.getPendingFetch(domain);
    if (pending) {
      return await pending;
    }
  }

  const fetchPromise = (async (): Promise<JWK[]> => {
    const url = `https://${domain}/.well-known/jwks.json`;
    let lastError: Error | undefined;
    let delay = retryDelay;

    for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, {
          signal: controller.signal,
          headers: {
            "User-Agent": userAgent,
            Accept: "application/json",
          },
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new TACNetworkError(`HTTP ${response.status}: ${response.statusText}`, TACErrorCodes.HTTP_ERROR);
        }

        let jwks: { keys: JWK[] };
        try {
          jwks = (await response.json()) as { keys: JWK[] };
        } catch (parseError) {
          throw new TACNetworkError(
            `Failed to parse JWKS response: ${(parseError as Error).message}`,
            TACErrorCodes.JWKS_PARSE_ERROR
          );
        }

        if (!jwks.keys) {
          throw new TACNetworkError("Invalid JWKS response: missing keys array", TACErrorCodes.JWKS_INVALID_FORMAT);
        }

        if (!Array.isArray(jwks.keys)) {
          throw new TACNetworkError("Invalid JWKS response: keys is not an array", TACErrorCodes.JWKS_INVALID_FORMAT);
        }

        if (cache) {
          cache.set(domain, jwks.keys);
          cache.deletePendingFetch(domain);
        }

        return jwks.keys;
      } catch (error) {
        // Transform AbortError to more descriptive timeout error
        if ((error as Error).name === "AbortError") {
          lastError = new TACNetworkError(`Request timeout after ${timeout}ms`, TACErrorCodes.NETWORK_TIMEOUT);
        } else {
          lastError = error as Error;
        }

        if (attempt <= maxRetries) {
          await new Promise((resolve) => setTimeout(resolve, delay));
          delay = Math.min(delay * 2, maxDelay);
        }
      }
    }

    if (cache) {
      cache.deletePendingFetch(domain);
    }

    throw new TACNetworkError(
      `Failed to fetch JWKS from ${domain} after ${maxRetries + 1} attempts: ${lastError?.message || 'Unknown error'}`,
      TACErrorCodes.JWKS_FETCH_FAILED
    );
  })();

  if (cache) {
    cache.setPendingFetch(domain, fetchPromise);
  }

  return await fetchPromise;
}

/**
 * Check if a key is currently valid based on nbf and exp
 * @param key - JWK object
 * @returns True if key is valid
 */
function isKeyValid(key: JWK): boolean {
  const now = Math.floor(Date.now() / 1000);

  // Check not before (nbf)
  if (key.nbf && now < key.nbf) {
    return false;
  }

  // Check expiration (exp)
  if (key.exp && now >= key.exp) {
    return false;
  }

  return true;
}

/**
 * Get key type from crypto KeyObject
 * @param key - Key object
 * @returns Key type (RSA)
 */
export function getKeyType(key: KeyObject): string {
  const keyType = key.asymmetricKeyType;

  if (keyType === "rsa" || keyType === "rsa-pss") {
    return "RSA";
  }

  throw new TACCryptoError(
    `Unsupported key type: ${keyType}. TAC Protocol requires RSA keys (minimum 2048-bit, 3072-bit recommended)`,
    TACErrorCodes.UNSUPPORTED_KEY_TYPE
  );
}

/**
 * Get appropriate algorithm for key type and use
 * @param key - Key object
 * @param use - 'sig' for signing, 'enc' for encryption
 * @returns Algorithm string
 */
export function getAlgorithmForKey(key: KeyObject, use: string = "sig"): string {
  const keyType = getKeyType(key);

  if (keyType === "RSA") {
    return use === "sig" ? "RS256" : "RSA-OAEP-256";
  }

  throw new TACCryptoError(
    `Unsupported key type: ${keyType}. TAC Protocol requires RSA keys (minimum 2048-bit, 3072-bit recommended)`,
    TACErrorCodes.UNSUPPORTED_KEY_TYPE
  );
}

/**
 * Find suitable encryption key from JWKS
 * @param keys - Array of JWK objects
 * @returns Encryption JWK or undefined
 */
export function findEncryptionKey(keys: JWK[]): JWK | undefined {
  // Filter valid RSA keys
  const validKeys = keys.filter((k) => isKeyValid(k) && k.kty === "RSA");

  for (const key of validKeys) {
    // Skip keys that are explicitly marked as signature-only
    if (key.use === "sig") {
      continue;
    }

    // Accept keys with no 'use' field (dual-purpose) or 'enc' use
    if (!key.use || key.use === "enc") {
      // Return key with appropriate encryption algorithm
      const encryptionKey = { ...key };
      encryptionKey.alg = "RSA-OAEP-256";
      return encryptionKey;
    }
  }

  return undefined;
}

/**
 * Find suitable signing key from JWKS
 * @param keys - Array of JWK objects
 * @param keyId - Optional key ID to match
 * @returns Signing JWK or undefined
 */
export function findSigningKey(keys: JWK[], keyId?: string): JWK | undefined {
  // Filter valid RSA keys
  const validKeys = keys.filter((k) => isKeyValid(k) && k.kty === "RSA");

  if (keyId) {
    const key = validKeys.find((k) => k.kid === keyId);
    if (key) {
      return key;
    }
  }

  // Look for appropriate RSA signing key
  const signingAlgs = ["RS256", "RS384", "RS512"];

  for (const alg of signingAlgs) {
    const key = validKeys.find((k) => (k.use === "sig" || !k.use) && (k.alg === alg || !k.alg));
    if (key) {
      return key;
    }
  }

  // Return any signing key
  return validKeys.find((k) => k.use === "sig" || !k.use);
}

/**
 * Convert public key to JWK format for bidirectional use (signing + encryption)
 * @param publicKey - Public key to convert
 * @param keyId - Optional key ID, will be generated if not provided
 * @returns JWK representation for dual-purpose use
 */
export async function publicKeyToJWK(publicKey: KeyObject | jose.KeyLike, keyId?: string): Promise<JWK> {
  if (!publicKey) {
    throw new TACCryptoError("No public key provided", TACErrorCodes.NO_PUBLIC_KEY);
  }

  // Use jose to export JWK
  let jwk: JWK;
  try {
    jwk = await jose.exportJWK(publicKey);
  } catch (error) {
    throw new TACCryptoError(
      `Failed to export public key to JWK: ${(error as Error).message}`,
      TACErrorCodes.JWK_EXPORT_FAILED
    );
  }

  // Verify key type is RSA
  if (jwk.kty !== "RSA") {
    throw new TACCryptoError(
      `Unsupported key type: ${jwk.kty}. TAC Protocol requires RSA keys (minimum 2048-bit, 3072-bit recommended)`,
      TACErrorCodes.UNSUPPORTED_KEY_TYPE
    );
  }

  // Generate key ID if not provided
  if (!keyId) {
    if ('export' in publicKey) {
      // For KeyObject, use DER export
      const derBytes = publicKey.export({
        type: "spki",
        format: "der",
      });
      const keyHash = crypto.createHash("sha256").update(derBytes).digest();
      keyId = keyHash.toString("base64url");
    } else {
      // For jose.KeyLike, use JWK content hash
      const jwkContent = JSON.stringify(jwk);
      keyId = crypto.createHash("sha256").update(jwkContent).digest("hex").substring(0, 16);
    }
  }

  // Return JWK without specifying 'use' for dual-purpose keys
  // Algorithm selection depends on context (signing vs encryption)
  const result: JWK = {
    ...jwk,
    kid: keyId,
    alg: "RS256", // Default for RSA
  };

  return result;
}
