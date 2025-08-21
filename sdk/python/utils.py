"""
Utility functions for the Trusted Agentic Commerce Protocol SDK
"""

import base64
import hashlib
import json
import time
import asyncio
from typing import Dict, List, Optional, Any, Union
import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

try:
    from .version import PROTOCOL_VERSION, SDK_VERSION, SDK_LANGUAGE
except ImportError:
    from version import PROTOCOL_VERSION, SDK_VERSION, SDK_LANGUAGE


class JWKSCache:
    """JWKS cache with TTL and pending request deduplication"""
    
    def __init__(self, timeout: int = 3600000):
        """
        Initialize JWKS cache
        
        Args:
            timeout: Cache timeout in milliseconds (default: 1 hour)
        """
        self.cache: Dict[str, Dict] = {}
        self.timeout = timeout
        self.pending_fetches: Dict[str, Any] = {}
    
    def get(self, domain: str) -> Optional[List[Dict]]:
        """
        Get cached keys if not expired
        
        Args:
            domain: Domain to get cached keys for
            
        Returns:
            Cached keys or None if expired/missing
        """
        cached = self.cache.get(domain)
        if cached and cached['expires'] > time.time() * 1000:
            return cached['keys']
        return None
    
    def set(self, domain: str, keys: List[Dict]):
        """
        Set keys in cache with expiry
        
        Args:
            domain: Domain to cache keys for
            keys: JWK keys to cache
        """
        # Calculate cache expiry - use the minimum of:
        # 1. Default cache timeout
        # 2. Earliest key expiration (if any keys have exp field)
        cache_expires = time.time() * 1000 + self.timeout
        
        # Check if any keys have exp field and adjust cache expiry
        key_expirations = [k.get('exp', 0) * 1000 for k in keys if k.get('exp')]
        
        if key_expirations:
            earliest_expiry = min(key_expirations)
            cache_expires = min(cache_expires, earliest_expiry)
        
        self.cache[domain] = {
            'keys': keys,
            'expires': cache_expires
        }
    
    def clear(self, domain: Optional[str] = None):
        """
        Clear cache for specific domain or all
        
        Args:
            domain: Domain to clear cache for, or None to clear all
        """
        if domain:
            self.cache.pop(domain, None)
            self.pending_fetches.pop(domain, None)
        else:
            self.cache.clear()
            self.pending_fetches.clear()
    
    def get_pending_fetch(self, domain: str):
        """Get pending fetch promise for deduplication"""
        return self.pending_fetches.get(domain)
    
    def set_pending_fetch(self, domain: str, fetch_task):
        """Store pending fetch task"""
        self.pending_fetches[domain] = fetch_task
    
    def delete_pending_fetch(self, domain: str):
        """Remove pending fetch"""
        self.pending_fetches.pop(domain, None)


async def fetch_jwks_with_retry(url: str, max_retries: int = 3, retry_delay: int = 1000, 
                              user_agent: Optional[str] = None) -> List[Dict]:
    """
    Fetch JWKS with exponential backoff retry and deduplication
    
    Args:
        url: JWKS URL to fetch
        max_retries: Maximum retry attempts
        retry_delay: Initial retry delay in milliseconds
        user_agent: User agent string (optional, defaults to TAC-Protocol user agent)
        
    Returns:
        List of JWK keys
        
    Raises:
        Exception: If all retries fail
    """
    if user_agent is None:
        user_agent = f'TAC-Protocol/{PROTOCOL_VERSION} ({SDK_LANGUAGE}/{SDK_VERSION})'
    
    last_error = None
    delay = retry_delay
    
    for attempt in range(max_retries + 1):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={
                        'User-Agent': user_agent,
                        'Accept': 'application/json'
                    }
                ) as response:
                    response.raise_for_status()
                    jwks = await response.json()
                    
                    if 'keys' not in jwks or not isinstance(jwks['keys'], list):
                        raise ValueError('Invalid JWKS format')
                    
                    return jwks['keys']
                    
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                await asyncio.sleep(delay / 1000)  # Convert to seconds
                delay = min(delay * 2, 30000)  # Cap at 30 seconds
            continue
    
    raise Exception(f'Failed to fetch JWKS from {url} after {max_retries + 1} attempts: {str(last_error)}')


def is_rsa_key(key: Any) -> bool:
    """
    Check if key is an RSA key
    
    Args:
        key: Cryptography key object
        
    Returns:
        True if key is RSA
    """
    return isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey))


def is_ec_key(key: Any) -> bool:
    """
    Check if key is an EC key
    
    Args:
        key: Cryptography key object
        
    Returns:
        True if key is EC
    """
    return isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey))




def get_key_type(key: Any) -> str:
    """
    Get key type for JWK
    
    Args:
        key: Cryptography key object
        
    Returns:
        Key type string (RSA or EC)
    """
    if is_rsa_key(key):
        return 'RSA'
    elif is_ec_key(key):
        return 'EC'
    else:
        raise ValueError('Unsupported key type')


def get_algorithm_for_key(key: Any, use: str = 'sig') -> str:
    """
    Get appropriate algorithm for key type and use
    
    Args:
        key: Cryptography key object
        use: 'sig' for signing, 'enc' for encryption
        
    Returns:
        Algorithm string
    """
    if is_rsa_key(key):
        return 'RS256' if use == 'sig' else 'RSA-OAEP-256'
    elif is_ec_key(key):
        if hasattr(key, 'curve'):
            curve = key.curve
        elif hasattr(key, 'public_key'):
            curve = key.public_key().curve
        else:
            curve = key.curve
        
        if isinstance(curve, ec.SECP256R1):
            return 'ES256' if use == 'sig' else 'ECDH-ES+A256KW'
        elif isinstance(curve, ec.SECP384R1):
            return 'ES384' if use == 'sig' else 'ECDH-ES+A256KW'
        elif isinstance(curve, ec.SECP521R1):
            return 'ES512' if use == 'sig' else 'ECDH-ES+A256KW'
        else:
            return 'ES256' if use == 'sig' else 'ECDH-ES+A256KW'
    else:
        raise ValueError('Unsupported key type')


def generate_key_id(public_key: Any) -> str:
    """
    Generate key ID from public key (SHA-256 hash)
    
    Args:
        public_key: Cryptography public key object
        
    Returns:
        Base64url-encoded key ID
    """
    # Serialize public key to DER format
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Calculate SHA-256 hash
    digest = hashlib.sha256(der_bytes).digest()
    
    # Return base64url-encoded hash
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


def is_key_valid(key: Dict) -> bool:
    """
    Check if a key is currently valid based on nbf and exp
    
    Args:
        key: JWK object
        
    Returns:
        True if key is valid
    """
    now = int(time.time())
    
    # Check not before (nbf)
    if key.get('nbf') and now < key['nbf']:
        return False
    
    # Check expiration (exp)
    if key.get('exp') and now >= key['exp']:
        return False
    
    return True


def find_encryption_key(keys: List[Dict]) -> Optional[Dict]:
    """
    Find suitable encryption key from JWKS (supports RSA and EC)
    
    Args:
        keys: Array of JWK objects
        
    Returns:
        Encryption JWK or None
    """
    # Supported algorithms by preference
    supported_algorithms = [
        ('RSA', ['RSA-OAEP-256', 'RSA-OAEP', 'RSA1_5']),
        ('EC', ['ECDH-ES+A256KW', 'ECDH-ES+A128KW', 'ECDH-ES'])
    ]
    
    # Filter valid keys
    valid_keys = [k for k in keys if is_key_valid(k)]
    
    # Try each key type and algorithm in order
    for kty, algs in supported_algorithms:
        kty_keys = [k for k in valid_keys if k.get('kty') == kty]
        
        for alg in algs:
            for key in kty_keys:
                if (key.get('use') == 'enc' or not key.get('use')) and key.get('alg') == alg:
                    return key
        
        # Return any encryption key of this type
        for key in kty_keys:
            if key.get('use') == 'enc' or not key.get('use'):
                return key
    
    return None


def find_signing_key(keys: List[Dict], key_id: Optional[str] = None) -> Optional[Dict]:
    """
    Find suitable signing key from JWKS (supports RSA and EC)
    
    Args:
        keys: Array of JWK objects
        key_id: Optional key ID to match
        
    Returns:
        Signing JWK or None
    """
    # Filter valid keys (supported types)
    valid_keys = [k for k in keys if is_key_valid(k) and k.get('kty') in ['RSA', 'EC']]
    
    if key_id:
        for key in valid_keys:
            if key.get('kid') == key_id:
                return key
    
    # Look for appropriate signing key
    for key in valid_keys:
        if key.get('use') == 'sig' or not key.get('use'):
            return key
    
    return None


def public_key_to_jwk(public_key: Any, key_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert public key to JWK format for bidirectional use (signing + encryption)
    
    Args:
        public_key: Cryptography public key object
        key_id: Optional key ID, will be generated if not provided
        
    Returns:
        JWK representation for dual-purpose use
    """
    if not public_key:
        raise ValueError('No public key provided')
    
    from jose import jwk
    
    # Generate key ID if not provided
    if not key_id:
        key_id = generate_key_id(public_key)
    
    key_type = get_key_type(public_key)
    
    # Create JWK based on key type
    if key_type == 'RSA':
        public_key_jwk = jwk.RSAKey(key=public_key, algorithm='RS256').to_dict()
        return {
            'kty': 'RSA',
            'n': public_key_jwk['n'],
            'e': public_key_jwk['e'],
            'alg': 'RS256',  # Default for RSA
            'kid': key_id
        }
    elif key_type == 'EC':
        public_key_jwk = jwk.ECKey(key=public_key, algorithm='ES256').to_dict()
        
        # Determine algorithm based on curve
        curve_name = public_key_jwk.get('crv', 'P-256')
        if curve_name == 'P-256':
            alg = 'ES256'
        elif curve_name == 'P-384':
            alg = 'ES384'
        elif curve_name == 'P-521':
            alg = 'ES512'
        else:
            alg = 'ES256'  # Default
        
        return {
            'kty': 'EC',
            'crv': curve_name,
            'x': public_key_jwk['x'],
            'y': public_key_jwk['y'],
            'alg': alg,
            'kid': key_id
        }
    else:
        raise ValueError(f'Unsupported key type: {key_type}')