"""
TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
Creates JWT with issuer and expiration, encrypts data for multiple recipients
"""

import base64
import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union

import jose.jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwe
from jose.backends import RSAKey

try:
    from .errors import TACCryptoError, TACErrorCodes, TACNetworkError, TACValidationError
    from .utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_encryption_key,
        get_algorithm_for_key,
        get_key_type,
        get_user_agent,
        public_key_to_jwk,
    )
    from .version import SCHEMA_VERSION
except ImportError:
    from errors import TACCryptoError, TACErrorCodes, TACNetworkError, TACValidationError
    from utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_encryption_key,
        get_algorithm_for_key,
        get_key_type,
        get_user_agent,
        public_key_to_jwk,
    )
    from version import SCHEMA_VERSION


class TACSender:
    """
    TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
    Creates JWT with issuer and expiration, encrypts data for multiple recipients
    """

    def __init__(
        self,
        domain: str,
        private_key: Union[str, Any],
        ttl: int = 3600,
        cache_timeout: int = 3600000,
        max_retries: int = 3,
        retry_delay: int = 1000,
        password: Optional[bytes] = None,
        hide_user_agent_version: bool = False,
    ):
        """
        Initialize TACSender

        Args:
            domain: Domain of the agent (required, used as 'iss' in JWT)
            private_key: Private key for signing (required)
            ttl: JWT expiry time in seconds (default: 3600)
            cache_timeout: JWKS cache timeout in ms (default: 3600000)
            max_retries: Max retry attempts for network requests (default: 3)
            retry_delay: Retry delay in ms (default: 1000)
            password: Password for encrypted private keys (default: None)
            hide_user_agent_version: If True, omit version details from User-Agent header (default: False)
        """
        if not domain:
            raise TACValidationError("domain is required in TACSender constructor", TACErrorCodes.DOMAIN_REQUIRED)
        if not private_key:
            raise TACValidationError(
                "privateKey is required in TACSender constructor", TACErrorCodes.PRIVATE_KEY_REQUIRED
            )

        self.domain = domain
        self._password = password
        self.set_private_key(private_key)  # This sets both private and public keys
        self.ttl = ttl
        self.jwks_cache = JWKSCache(cache_timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.hide_user_agent_version = hide_user_agent_version
        self.recipient_data: Dict[str, Dict] = {}

    def set_private_key(self, private_key: Union[str, Any], password: Optional[bytes] = None):
        """
        Set private key and automatically derive public key

        Args:
            private_key: Private key object or PEM string
            password: Password for encrypted private keys (default: uses constructor password)
        """
        key_password = password if password is not None else getattr(self, "_password", None)
        try:
            if isinstance(private_key, str):
                self.private_key = serialization.load_pem_private_key(private_key.encode(), password=key_password)
            else:
                self.private_key = private_key
        except Exception as error:
            raise TACCryptoError(f"Invalid key data: {str(error)}", TACErrorCodes.INVALID_KEY_DATA)

        # Verify it's a supported key type
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise TACCryptoError(
                "TAC Protocol requires RSA keys (minimum 2048-bit, 3072-bit recommended)",
                TACErrorCodes.UNSUPPORTED_KEY_TYPE
            )

        # Always derive public key from private key
        self.public_key = self.private_key.public_key()

        # Store key type and algorithm
        self.key_type = get_key_type(self.private_key)
        self.signing_algorithm = get_algorithm_for_key(self.private_key, "sig")

    def generate_key_id(self) -> str:
        """
        Generate key ID from public key

        Returns:
            Base64url encoded SHA-256 hash of public key
        """
        if not self.public_key:
            raise TACValidationError("No public key available. Load or set keys first.", TACErrorCodes.NO_PUBLIC_KEY)

        key_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.urlsafe_b64encode(hashlib.sha256(key_data).digest()).decode().rstrip("=")

    async def fetch_jwks(self, domain: str, force_refresh: bool = False) -> List[Dict]:
        """
        Fetch JWKS from a domain's well-known endpoint

        Args:
            domain: Domain to fetch JWKS from
            force_refresh: Force cache bypass

        Returns:
            Array of JWK objects
        """
        return await fetch_jwks_with_retry(
            domain,
            cache=self.jwks_cache,
            max_retries=self.max_retries,
            retry_delay=self.retry_delay,
            max_delay=self.retry_delay * 30,
            user_agent=get_user_agent(hide_version=self.hide_user_agent_version),
            force_refresh=force_refresh,
        )

    async def add_recipient_data(self, domain: str, data: Dict[str, Any]):
        """
        Add data for a specific recipient domain
        Data will be encrypted when generate_tac_message is called

        Args:
            domain: Recipient domain
            data: Data to encrypt for this recipient
        """
        if not domain or not isinstance(domain, str) or domain.strip() == "":
            raise TACValidationError("Domain cannot be empty or None", TACErrorCodes.INVALID_DOMAIN)

        if data is None:
            raise TACValidationError("Data cannot be None", TACErrorCodes.INVALID_DATA)

        # Store the data - encryption happens later in generate_tac_message
        self.recipient_data[domain] = data

    def set_recipients_data(self, recipients_data: Dict[str, Dict[str, Any]]):
        """
        Set recipients data (clears existing data first)

        Args:
            recipients_data: Object mapping domains to their data
                Example: { 'merchant.com': { order: '123' }, 'vendor.com': { shipment: 'abc' } }
        """
        self.recipient_data = recipients_data.copy()

    def clear_recipient_data(self):
        """Clear all recipient data"""
        self.recipient_data = {}

    async def generate_tac_message(self) -> str:
        """
        Generate TAC-Protocol message with signed JWT and encrypted data

        Returns:
            Base64-encoded TAC-Protocol message (ready for HTTP headers or body)
        """
        if not self.private_key:
            raise TACValidationError("No private key available. Load or set keys first.", TACErrorCodes.NO_PRIVATE_KEY)

        if not self.recipient_data:
            raise TACValidationError(
                "No recipient data added. Use add_recipient_data() first.", TACErrorCodes.NO_RECIPIENT_DATA
            )

        # Prepare recipient public keys map
        recipient_public_keys = {}

        # Fetch all recipient public keys in parallel (simulated with sequential for now)
        for domain in self.recipient_data.keys():
            try:
                jwks = await self.fetch_jwks(domain)
                encryption_key = find_encryption_key(jwks)
                if not encryption_key:
                    raise TACNetworkError(
                        f"No suitable encryption key found for {domain}", TACErrorCodes.NO_ENCRYPTION_KEY_FOUND
                    )
                recipient_public_keys[domain] = encryption_key
            except Exception as error:
                raise TACNetworkError(
                    f"Failed to fetch keys for {domain}: {str(error)}", TACErrorCodes.JWKS_FETCH_FAILED
                )

        # Create individual JWE for each recipient with their specific data
        now = int(time.time())
        recipient_jwes = []

        for domain, jwk_dict in recipient_public_keys.items():
            # Generate unique JWT ID to prevent replay attacks
            jti = str(uuid.uuid4())

            # Create JWT payload with only this recipient's data
            payload = {
                "iss": self.domain,
                "exp": now + self.ttl,
                "iat": now,
                "aud": domain,  # Audience claim for this specific recipient
                "jti": jti,  # Unique JWT ID to prevent replay attacks
                "data": self.recipient_data[domain],  # Only this recipient's data
            }

            # Step 1: Create and SIGN the JWT with sender's private key (JWS)
            key_id = self.generate_key_id()
            try:
                # Create JWK from private key for signing
                private_key_jwk = RSAKey(key=self.private_key, algorithm=self.signing_algorithm)

                signed_jwt = jose.jwt.encode(
                    payload, private_key_jwk, algorithm=self.signing_algorithm, headers={"kid": key_id, "typ": "JWT"}
                )
            except Exception as error:
                raise TACCryptoError(f"JWT signing failed: {str(error)}", TACErrorCodes.JWT_SIGNING_FAILED)

            # Step 2: ENCRYPT the signed JWT with recipient's public key (JWE)
            algorithm = jwk_dict.get("alg", "RSA-OAEP-256")

            try:
                # Encrypt the signed JWT for this recipient
                encrypted_jwt = jwe.encrypt(
                    signed_jwt.encode("utf-8"), jwk_dict, algorithm=algorithm, encryption="A256GCM", cty="JWT"
                )
            except Exception as error:
                raise TACCryptoError(f"Encryption failed for {domain}: {str(error)}", TACErrorCodes.ENCRYPTION_FAILED)

            recipient_jwes.append(
                {
                    "kid": domain,
                    "jwe": encrypted_jwt.decode("utf-8") if isinstance(encrypted_jwt, bytes) else encrypted_jwt,
                }
            )

        # Create multi-recipient container
        multi_recipient_message = {"version": SCHEMA_VERSION, "recipients": recipient_jwes}

        message_json = json.dumps(multi_recipient_message)
        return base64.b64encode(message_json.encode("utf-8")).decode("utf-8")

    async def get_public_jwk(self) -> Dict[str, Any]:
        """
        Get public key as JWK for publishing (bidirectional use)

        Returns:
            JWK representation of the public key
        """
        return public_key_to_jwk(self.public_key, self.generate_key_id())

    def clear_cache(self, domain: Optional[str] = None):
        """
        Clear JWKS cache

        Args:
            domain: Specific domain to clear, or None for all
        """
        self.jwks_cache.clear(domain)
