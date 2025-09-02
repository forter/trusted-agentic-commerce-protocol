"""
Utility functions for the Trusted Agentic Commerce Protocol SDK
"""

import asyncio
import base64
import hashlib
import time
from typing import Any, Dict, List, Optional

import aiohttp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

try:
    from .errors import TACCryptoError, TACErrorCodes, TACNetworkError
    from .version import SCHEMA_VERSION, SDK_LANGUAGE, SDK_VERSION
except ImportError:
    from errors import TACCryptoError, TACErrorCodes, TACNetworkError
    from version import SCHEMA_VERSION, SDK_LANGUAGE, SDK_VERSION


def get_user_agent() -> str:
    """Get User-Agent string"""
    return f"TAC-Protocol/{SCHEMA_VERSION} ({SDK_LANGUAGE}/{SDK_VERSION})"


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
        if cached and cached["expires"] > time.time() * 1000:
            return cached["keys"]
        return None

    def set(self, domain: str, keys: List[Dict]):
        """
        Set keys in cache with expiry

        Args:
            domain: Domain to cache keys for
            keys: JWK keys to cache
        """
        # Don't cache None keys
        if keys is None:
            return

        # Calculate cache expiry - use the minimum of:
        # 1. Default cache timeout
        # 2. Earliest key expiration (if any keys have exp field)
        cache_expires = time.time() * 1000 + self.timeout

        # Check if any keys have exp field and adjust cache expiry
        key_expirations = [k.get("exp", 0) * 1000 for k in keys if k.get("exp")]

        if key_expirations:
            earliest_expiry = min(key_expirations)
            cache_expires = min(cache_expires, earliest_expiry)

        self.cache[domain] = {"keys": keys, "expires": cache_expires}

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


async def fetch_jwks_with_retry(
    domain: str,
    cache: Optional[JWKSCache] = None,
    max_retries: int = 3,
    retry_delay: int = 1000,
    max_delay: int = 30000,
    timeout: int = 10000,
    user_agent: Optional[str] = None,
    force_refresh: bool = False,
) -> List[Dict]:
    """
    Fetch JWKS with exponential backoff retry and deduplication

    Args:
        domain: Domain to fetch JWKS from
        cache: Optional cache instance
        max_retries: Maximum number of retry attempts
        retry_delay: Initial delay in milliseconds
        max_delay: Maximum delay in milliseconds
        timeout: Request timeout in milliseconds
        user_agent: User agent string
        force_refresh: Force refresh bypassing cache

    Returns:
        List of JWK objects
    """
    if user_agent is None:
        user_agent = get_user_agent()

    if cache and not force_refresh:
        cached = cache.get(domain)
        if cached:
            return cached

        pending = cache.get_pending_fetch(domain)
        if pending:
            return await pending

    async def fetch_impl():
        url = f"https://{domain}/.well-known/jwks.json"
        last_error = None
        delay = retry_delay / 1000.0  # Convert to seconds

        for attempt in range(1, max_retries + 2):  # +1 for initial attempt
            try:
                client_timeout = aiohttp.ClientTimeout(total=timeout / 1000.0)
                headers = {"User-Agent": user_agent, "Accept": "application/json"}

                async with aiohttp.ClientSession(timeout=client_timeout) as session:
                    async with session.get(url, headers=headers) as response:
                        if response.status != 200:
                            raise TACNetworkError(
                                f"HTTP {response.status}: {response.reason}", TACErrorCodes.HTTP_ERROR
                            )

                        try:
                            jwks = await response.json()
                        except Exception as parse_error:
                            raise TACNetworkError(
                                f"Failed to parse JWKS response: {str(parse_error)}", TACErrorCodes.JWKS_PARSE_ERROR
                            )

                        if "keys" not in jwks:
                            raise TACNetworkError(
                                "Invalid JWKS response: missing keys array", TACErrorCodes.JWKS_INVALID_FORMAT
                            )

                        if not isinstance(jwks["keys"], list):
                            raise TACNetworkError(
                                "Invalid JWKS response: keys is not an array", TACErrorCodes.JWKS_INVALID_FORMAT
                            )

                        if cache:
                            cache.set(domain, jwks["keys"])
                            cache.delete_pending_fetch(domain)

                        return jwks["keys"]

            except asyncio.TimeoutError:
                last_error = TACNetworkError(f"Request timeout after {timeout}ms", TACErrorCodes.NETWORK_TIMEOUT)
            except Exception as error:
                last_error = error

            if attempt <= max_retries:
                await asyncio.sleep(delay)
                delay = min(delay * 2, max_delay / 1000.0)

        if cache:
            cache.delete_pending_fetch(domain)

        raise TACNetworkError(
            f"Failed to fetch JWKS from {domain} after {max_retries + 1} attempts: {str(last_error)}",
            TACErrorCodes.JWKS_FETCH_FAILED,
        )

    fetch_task = asyncio.create_task(fetch_impl())

    if cache:
        cache.set_pending_fetch(domain, fetch_task)

    return await fetch_task


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
    if key.get("nbf") and now < key["nbf"]:
        return False

    # Check expiration (exp)
    if key.get("exp") and now >= key["exp"]:
        return False

    return True


def get_key_type(key) -> str:
    """
    Get key type from cryptography key object

    Args:
        key: Key object

    Returns:
        Key type (RSA or EC)
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA"
    elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "EC"
    else:
        raise TACCryptoError(f"Unsupported key type: {type(key)}", TACErrorCodes.UNSUPPORTED_KEY_TYPE)


def get_algorithm_for_key(key, use: str = "sig") -> str:
    """
    Get appropriate algorithm for key type and use

    Args:
        key: Key object
        use: 'sig' for signing, 'enc' for encryption

    Returns:
        Algorithm string
    """
    key_type = get_key_type(key)

    if key_type == "RSA":
        return "RS256" if use == "sig" else "RSA-OAEP-256"
    elif key_type == "EC":
        if use == "sig":
            # Extract curve from public key
            if hasattr(key, "curve"):
                curve = key.curve
            elif hasattr(key, "public_key"):
                curve = key.public_key().curve
            else:
                return "ES256"  # Default

            curve_name = curve.name
            if curve_name in ["secp256r1", "prime256v1"]:
                return "ES256"
            elif curve_name == "secp384r1":
                return "ES384"
            elif curve_name == "secp521r1":
                return "ES512"
            else:
                return "ES256"
        else:
            return "ECDH-ES+A256KW"

    raise TACCryptoError(f"Unsupported key type: {key_type}", TACErrorCodes.UNSUPPORTED_KEY_TYPE)


def find_encryption_key(keys: List[Dict]) -> Optional[Dict]:
    """
    Find suitable encryption key from JWKS (supports RSA and EC bidirectional keys)

    Args:
        keys: Array of JWK objects

    Returns:
        Encryption JWK or None
    """
    # Filter valid keys (supported types for bidirectional use)
    valid_keys = [k for k in keys if is_key_valid(k) and k.get("kty") in ["RSA", "EC"]]

    # Prefer RSA keys for compatibility, then EC
    key_types = ["RSA", "EC"]

    for key_type in key_types:
        type_keys = [k for k in valid_keys if k.get("kty") == key_type]

        for key in type_keys:
            # Skip keys that are explicitly marked as signature-only
            if key.get("use") == "sig":
                continue

            # Accept keys with no 'use' field (dual-purpose) or 'enc' use
            if not key.get("use") or key.get("use") == "enc":
                # Return key with appropriate encryption algorithm
                encryption_key = key.copy()

                if key.get("kty") == "RSA":
                    encryption_key["alg"] = "RSA-OAEP-256"
                elif key.get("kty") == "EC":
                    encryption_key["alg"] = "ECDH-ES+A256KW"

                return encryption_key

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
    valid_keys = [k for k in keys if is_key_valid(k) and k.get("kty") in ["RSA", "EC"]]

    if key_id:
        key = next((k for k in valid_keys if k.get("kid") == key_id), None)
        if key:
            return key

    # Look for appropriate signing key by type
    signing_algs = {"RSA": ["RS256", "RS384", "RS512"], "EC": ["ES256", "ES384", "ES512"]}

    for kty, algs in signing_algs.items():
        for alg in algs:
            key = next(
                (
                    k
                    for k in valid_keys
                    if k.get("kty") == kty
                    and (k.get("use") == "sig" or not k.get("use"))
                    and (k.get("alg") == alg or not k.get("alg"))
                ),
                None,
            )
            if key:
                return key

    # Return any signing key
    return next((k for k in valid_keys if k.get("use") == "sig" or not k.get("use")), None)


def public_key_to_jwk(public_key, key_id: Optional[str] = None) -> Dict:
    """
    Convert public key to JWK format for bidirectional use (signing + encryption)

    Args:
        public_key: Public key to convert
        key_id: Optional key ID, will be generated if not provided

    Returns:
        JWK representation for dual-purpose use
    """
    if not public_key:
        raise TACCryptoError("No public key provided", TACErrorCodes.NO_PUBLIC_KEY)

    # Generate key ID if not provided
    if not key_id:
        try:
            der_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except AttributeError:
            # Already a public key
            der_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        key_hash = hashlib.sha256(der_bytes).digest()
        key_id = base64.urlsafe_b64encode(key_hash).decode("ascii").rstrip("=")

    key_type = get_key_type(public_key)

    if key_type == "RSA":
        numbers = public_key.public_numbers()

        # Convert to base64url encoding
        def int_to_base64url(value):
            byte_length = (value.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(value.to_bytes(byte_length, "big")).decode("ascii").rstrip("=")

        jwk = {
            "kty": "RSA",
            "kid": key_id,
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
            "alg": "RS256",  # Default for RSA
        }

    elif key_type == "EC":
        numbers = public_key.public_numbers()
        curve = public_key.curve

        # Determine curve parameters
        if curve.name in ["secp256r1", "prime256v1"]:
            crv = "P-256"
            coord_size = 32
            alg = "ES256"
        elif curve.name == "secp384r1":
            crv = "P-384"
            coord_size = 48
            alg = "ES384"
        elif curve.name == "secp521r1":
            crv = "P-521"
            coord_size = 66
            alg = "ES512"
        else:
            raise TACCryptoError(f"Unsupported curve: {curve.name}", TACErrorCodes.UNSUPPORTED_KEY_TYPE)

        # Convert coordinates to base64url encoding
        def coord_to_base64url(value, size):
            return base64.urlsafe_b64encode(value.to_bytes(size, "big")).decode("ascii").rstrip("=")

        jwk = {
            "kty": "EC",
            "kid": key_id,
            "crv": crv,
            "x": coord_to_base64url(numbers.x, coord_size),
            "y": coord_to_base64url(numbers.y, coord_size),
            "alg": alg,
        }

    else:
        raise TACCryptoError(f"Unsupported key type: {key_type}", TACErrorCodes.UNSUPPORTED_KEY_TYPE)

    return jwk
