import crypto, { KeyObject } from 'node:crypto';
import * as jose from 'jose';
import {
  JWK,
  CachedJWKS,
  FetchOptions
} from './sdk-types.js';
import { PROTOCOL_VERSION, SDK_VERSION, SDK_LANGUAGE } from './version.js';

/**
 * JWKS cache with TTL and pending request deduplication
 */
export class JWKSCache {
  private cache = new Map<string, CachedJWKS>();
  private timeout: number;
  private pendingFetches = new Map<string, Promise<JWK[]>>();

  /**
   * @param timeout - Cache timeout in milliseconds
   */
  constructor(timeout: number = 3600000) {
    this.timeout = timeout;
  }

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
    const keyExpirations = keys
      .filter(k => k.exp)
      .map(k => k.exp! * 1000); // Convert to milliseconds
    
    if (keyExpirations.length > 0) {
      const earliestExpiry = Math.min(...keyExpirations);
      cacheExpires = Math.min(cacheExpires, earliestExpiry);
    }
    
    this.cache.set(domain, {
      keys,
      expires: cacheExpires
    });
  }

  /**
   * Clear cache for specific domain or all
   * @param domain - Domain to clear, or undefined for all
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
    initialDelay = 1000,
    maxDelay = 30000,
    userAgent = `TAP-Protocol/${PROTOCOL_VERSION} (${SDK_LANGUAGE}/${SDK_VERSION})`,
    forceRefresh = false
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
    let lastError: Error;
    let delay = initialDelay;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(url, {
          signal: controller.signal,
          headers: {
            'User-Agent': userAgent,
            'Accept': 'application/json'
          }
        });

        clearTimeout(timeout);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const jwks: any = await response.json();

        if (!jwks.keys || !Array.isArray(jwks.keys)) {
          throw new Error('Invalid JWKS format');
        }

        if (cache) {
          cache.set(domain, jwks.keys);
          cache.deletePendingFetch(domain);
        }

        return jwks.keys;

      } catch (error) {
        lastError = error as Error;

        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, delay));
          delay = Math.min(delay * 2, maxDelay);
        }
      }
    }

    if (cache) {
      cache.deletePendingFetch(domain);
    }

    throw new Error(`Failed to fetch JWKS from ${domain} after ${maxRetries} attempts: ${lastError!.message}`);
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
 * Check if key is an RSA key
 * @param key - Cryptography key object
 * @returns True if key is RSA
 */
export function isRSAKey(key: KeyObject): boolean {
  return key.asymmetricKeyType === 'rsa' || key.asymmetricKeyType === 'rsa-pss';
}

/**
 * Check if key is an EC key
 * @param key - Cryptography key object
 * @returns True if key is EC
 */
export function isECKey(key: KeyObject): boolean {
  return key.asymmetricKeyType === 'ec';
}

/**
 * Get key type from crypto KeyObject
 * @param key - Key object
 * @returns Key type (RSA or EC)
 */
export function getKeyType(key: KeyObject): string {
  if (isRSAKey(key)) return 'RSA';
  if (isECKey(key)) return 'EC';
  
  throw new Error(`Unsupported key type: ${key.asymmetricKeyType}`);
}

/**
 * Get appropriate algorithm for key type and use
 * @param key - Key object
 * @param use - 'sig' for signing, 'enc' for encryption
 * @returns Algorithm string
 */
export function getAlgorithmForKey(key: KeyObject, use: 'sig' | 'enc' = 'sig'): string {
  const keyType = getKeyType(key);
  
  if (keyType === 'RSA') {
    return use === 'sig' ? 'RS256' : 'RSA-OAEP-256';
  } else if (keyType === 'EC') {
    const keyDetail = (key as any).asymmetricKeyDetails;
    const curve = keyDetail?.namedCurve;
    
    if (use === 'sig') {
      switch (curve) {
        case 'P-256':
        case 'prime256v1':
        case 'secp256r1':
          return 'ES256';
        case 'P-384':
        case 'secp384r1':
          return 'ES384';
        case 'P-521':
        case 'secp521r1':
          return 'ES512';
        default:
          return 'ES256';
      }
    } else {
      return 'ECDH-ES+A256KW';
    }
  }
  
  throw new Error(`Unsupported key type: ${keyType}`);
}

/**
 * Generate key ID from public key (SHA-256 hash)
 * @param publicKey - Cryptography public key object
 * @returns Base64url-encoded key ID
 */
export function generateKeyId(publicKey: KeyObject): string {
  // Serialize public key to DER format
  const derBytes = publicKey.export({
    type: 'spki',
    format: 'der'
  }) as Buffer;
  
  // Calculate SHA-256 hash
  const keyHash = crypto.createHash('sha256').update(derBytes).digest();
  
  // Return base64url-encoded hash
  return keyHash.toString('base64url');
}

/**
 * Find suitable encryption key from JWKS (supports RSA and EC)
 * @param keys - Array of JWK objects
 * @returns Encryption JWK or undefined
 */
export function findEncryptionKey(keys: JWK[]): JWK | undefined {
  // Supported algorithms by preference
  const supportedAlgorithms = [
    { kty: 'RSA', algs: ['RSA-OAEP-256', 'RSA-OAEP', 'RSA1_5'] },
    { kty: 'EC', algs: ['ECDH-ES+A256KW', 'ECDH-ES+A128KW', 'ECDH-ES'] }
  ];
  
  // Filter valid keys
  const validKeys = keys.filter(k => isKeyValid(k));
  
  // Try each key type and algorithm in order
  for (const { kty, algs } of supportedAlgorithms) {
    const ktyKeys = validKeys.filter(k => k.kty === kty);
    
    for (const alg of algs) {
      const key = ktyKeys.find(k => 
        (k.use === 'enc' || !k.use) && 
        k.alg === alg
      );
      if (key) return key;
    }
    
    // Return any encryption key of this type
    const anyKey = ktyKeys.find(k => k.use === 'enc' || !k.use);
    if (anyKey) return anyKey;
  }
  
  return undefined;
}

/**
 * Find suitable signing key from JWKS (supports RSA and EC)
 * @param keys - Array of JWK objects
 * @param keyId - Optional key ID to match
 * @returns Signing JWK or undefined
 */
export function findSigningKey(keys: JWK[], keyId?: string): JWK | undefined {
  // Filter valid keys (supported types)
  const validKeys = keys.filter(k => isKeyValid(k) && ['RSA', 'EC'].includes(k.kty));
  
  if (keyId) {
    const key = validKeys.find(k => k.kid === keyId);
    if (key) return key;
  }
  
  // Look for appropriate signing key by type
  const signingAlgs = {
    'RSA': ['RS256', 'RS384', 'RS512'],
    'EC': ['ES256', 'ES384', 'ES512']
  };
  
  for (const [kty, algs] of Object.entries(signingAlgs)) {
    for (const alg of algs) {
      const key = validKeys.find(k => 
        k.kty === kty &&
        (k.use === 'sig' || !k.use) &&
        (k.alg === alg || !k.alg)
      );
      if (key) return key;
    }
  }
  
  // Return any signing key
  return validKeys.find(k => k.use === 'sig' || !k.use);
}

/**
 * Convert public key to JWK format for bidirectional use (signing + encryption)
 * @param publicKey - Public key to convert
 * @param keyId - Optional key ID, will be generated if not provided
 * @returns JWK representation for dual-purpose use
 */
export async function publicKeyToJWK(publicKey: KeyObject, keyId?: string): Promise<JWK> {
  if (!publicKey) {
    throw new Error('No public key provided');
  }
  
  // Use jose to export JWK
  const jwk = await jose.exportJWK(publicKey);
  
  // Generate key ID if not provided
  if (!keyId) {
    keyId = generateKeyId(publicKey);
  }
  
  const keyType = getKeyType(publicKey);
  
  // Return JWK without specifying 'use' for dual-purpose keys
  // Algorithm selection depends on context (signing vs encryption)
  const result: JWK = {
    kty: jwk.kty as 'RSA' | 'EC' | 'OKP',
    kid: keyId,
    ...(jwk.n && { n: jwk.n }),
    ...(jwk.e && { e: jwk.e }),
    ...(jwk.x && { x: jwk.x }),
    ...(jwk.y && { y: jwk.y }),
    ...(jwk.crv && { crv: jwk.crv })
  };
  
  // Add default algorithm based on key type for compatibility
  if (keyType === 'RSA') {
    result.alg = 'RS256'; // Default for RSA
  } else if (keyType === 'EC') {
    const keyDetail = (publicKey as any).asymmetricKeyDetails;
    const curve = keyDetail?.namedCurve;
    
    switch (curve) {
      case 'P-256':
      case 'prime256v1':
      case 'secp256r1':
        result.alg = 'ES256';
        break;
      case 'P-384':
      case 'secp384r1':
        result.alg = 'ES384';
        break;
      case 'P-521':
      case 'secp521r1':
        result.alg = 'ES512';
        break;
      default:
        result.alg = 'ES256';
    }
  }
  
  return result;
}