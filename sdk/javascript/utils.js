import { PROTOCOL_VERSION, SDK_VERSION, SDK_LANGUAGE } from './version.js';

/**
 * JWKS cache with TTL and pending request deduplication
 */
export class JWKSCache {
  /**
   * @param {number} timeout - Cache timeout in milliseconds
   */
  constructor(timeout = 3600000) {
    this.cache = new Map();
    this.timeout = timeout;
    this.pendingFetches = new Map();
  }

  /**
   * Get cached keys if not expired
   * @param {string} domain - Domain to get cached keys for
   * @returns {Array|null} Cached keys or null if expired/missing
   */
  get(domain) {
    const cached = this.cache.get(domain);
    if (cached && cached.expires > Date.now()) {
      return cached.keys;
    }
    return null;
  }

  /**
   * Set keys in cache with expiry
   * @param {string} domain - Domain to cache keys for
   * @param {Array} keys - JWK keys to cache
   */
  set(domain, keys) {
    // Calculate cache expiry - use the minimum of:
    // 1. Default cache timeout
    // 2. Earliest key expiration (if any keys have exp field)
    let cacheExpires = Date.now() + this.timeout;
    
    // Check if any keys have exp field and adjust cache expiry
    const keyExpirations = keys
      .filter(k => k.exp)
      .map(k => k.exp * 1000); // Convert to milliseconds
    
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
   * @param {string} domain - Domain to clear, or null for all
   */
  clear(domain = null) {
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
   * @param {string} domain - Domain to get pending fetch for
   * @returns {Promise|undefined} Pending fetch promise
   */
  getPendingFetch(domain) {
    return this.pendingFetches.get(domain);
  }

  /**
   * Store pending fetch promise
   * @param {string} domain - Domain of pending fetch
   * @param {Promise} promise - Fetch promise
   */
  setPendingFetch(domain, promise) {
    this.pendingFetches.set(domain, promise);
  }

  /**
   * Remove pending fetch
   * @param {string} domain - Domain to remove pending fetch for
   */
  deletePendingFetch(domain) {
    this.pendingFetches.delete(domain);
  }
}

/**
 * Fetch JWKS with exponential backoff retry and deduplication
 * @param {string} domain - Domain to fetch JWKS from
 * @param {Object} options - Fetch options
 * @returns {Promise<Array>} Array of JWK objects
 */
export async function fetchJWKSWithRetry(domain, options = {}) {
  const {
    cache = null,
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 30000,
    userAgent = `TAC-Protocol/${PROTOCOL_VERSION} (${SDK_LANGUAGE}/${SDK_VERSION})`,
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

  const fetchPromise = (async () => {
    const url = `https://${domain}/.well-known/jwks.json`;
    let lastError;
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

        const jwks = await response.json();

        if (!jwks.keys || !Array.isArray(jwks.keys)) {
          throw new Error('Invalid JWKS format');
        }

        if (cache) {
          cache.set(domain, jwks.keys);
          cache.deletePendingFetch(domain);
        }

        return jwks.keys;

      } catch (error) {
        lastError = error;

        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, delay));
          delay = Math.min(delay * 2, maxDelay);
        }
      }
    }

    if (cache) {
      cache.deletePendingFetch(domain);
    }

    throw new Error(`Failed to fetch JWKS from ${domain} after ${maxRetries} attempts: ${lastError.message}`);
  })();

  if (cache) {
    cache.setPendingFetch(domain, fetchPromise);
  }

  return await fetchPromise;
}

/**
 * Check if a key is currently valid based on nbf and exp
 * @param {Object} key - JWK object
 * @returns {boolean} True if key is valid
 */
function isKeyValid(key) {
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
 * @param {crypto.KeyObject} key - Key object
 * @returns {string} Key type (RSA or EC)
 */
export function getKeyType(key) {
  const keyType = key.asymmetricKeyType;
  
  if (keyType === 'rsa' || keyType === 'rsa-pss') return 'RSA';
  if (keyType === 'ec') return 'EC';
  
  throw new Error(`Unsupported key type: ${keyType}`);
}

/**
 * Get appropriate algorithm for key type and use
 * @param {crypto.KeyObject} key - Key object
 * @param {string} use - 'sig' for signing, 'enc' for encryption
 * @returns {string} Algorithm string
 */
export function getAlgorithmForKey(key, use = 'sig') {
  const keyType = getKeyType(key);
  const keyDetail = key.asymmetricKeyDetails;
  
  if (keyType === 'RSA') {
    return use === 'sig' ? 'RS256' : 'RSA-OAEP-256';
  } else if (keyType === 'EC') {
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
 * Find suitable encryption key from JWKS (supports RSA and EC bidirectional keys)
 * @param {Array} keys - Array of JWK objects
 * @returns {Object|undefined} Encryption JWK or undefined
 */
export function findEncryptionKey(keys) {
  // Filter valid keys (supported types for bidirectional use)
  const validKeys = keys.filter(k => isKeyValid(k) && ['RSA', 'EC'].includes(k.kty));
  
  // Prefer RSA keys for compatibility, then EC
  const keyTypes = ['RSA', 'EC'];
  
  for (const keyType of keyTypes) {
    const typeKeys = validKeys.filter(k => k.kty === keyType);
    
    for (const key of typeKeys) {
      // Skip keys that are explicitly marked as signature-only
      if (key.use === 'sig') continue;
      
      // Accept keys with no 'use' field (dual-purpose) or 'enc' use
      if (!key.use || key.use === 'enc') {
        // Return key with appropriate encryption algorithm
        const encryptionKey = { ...key };
        
        if (key.kty === 'RSA') {
          encryptionKey.alg = 'RSA-OAEP-256';
        } else if (key.kty === 'EC') {
          encryptionKey.alg = 'ECDH-ES+A256KW';
        }
        
        return encryptionKey;
      }
    }
  }
  
  return undefined;
}

/**
 * Find suitable signing key from JWKS (supports RSA and EC)
 * @param {Array} keys - Array of JWK objects
 * @param {string} keyId - Optional key ID to match
 * @returns {Object|undefined} Signing JWK or undefined
 */
export function findSigningKey(keys, keyId = null) {
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
 * @param {crypto.KeyObject} publicKey - Public key to convert
 * @param {string} keyId - Optional key ID, will be generated if not provided
 * @returns {Promise<Object>} JWK representation for dual-purpose use
 */
export async function publicKeyToJWK(publicKey, keyId = null) {
  if (!publicKey) {
    throw new Error('No public key provided');
  }
  
  const jose = await import('jose');
  
  // Use jose to export JWK
  const jwk = await jose.exportJWK(publicKey);
  
  // Generate key ID if not provided
  if (!keyId) {
    const crypto = await import('node:crypto');
    const derBytes = publicKey.export({
      type: 'spki',
      format: 'der'
    });
    const keyHash = crypto.createHash('sha256').update(derBytes).digest();
    keyId = keyHash.toString('base64url');
  }
  
  const keyType = getKeyType(publicKey);
  
  // Return JWK without specifying 'use' for dual-purpose keys
  // Algorithm selection depends on context (signing vs encryption)
  const result = {
    ...jwk,
    kid: keyId
  };
  
  // Add default algorithm based on key type for compatibility
  if (keyType === 'RSA') {
    result.alg = 'RS256'; // Default for RSA
  } else if (keyType === 'EC') {
    const keyDetail = publicKey.asymmetricKeyDetails;
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