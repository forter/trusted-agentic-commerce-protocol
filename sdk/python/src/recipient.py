"""
TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
Handles TAC-Protocol message verification and decryption
"""

import base64
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Union

import jose.jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwe
from jose.exceptions import JWTError

try:
    from .errors import TACCryptoError, TACErrorCodes, TACMessageError, TACNetworkError, TACValidationError
    from .utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_signing_key,
        get_algorithm_for_key,
        get_key_type,
        get_user_agent,
        public_key_to_jwk,
    )
except ImportError:
    from errors import TACCryptoError, TACErrorCodes, TACMessageError, TACNetworkError, TACValidationError
    from utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_signing_key,
        get_algorithm_for_key,
        get_key_type,
        get_user_agent,
        public_key_to_jwk,
    )


class TACRecipient:
    """
    TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
    Handles TAC-Protocol message verification and decryption
    """

    def __init__(
        self,
        domain: str,
        private_key: Union[str, Any],
        cache_timeout: int = 3600000,
        max_retries: int = 3,
        retry_delay: int = 1000,
        clock_tolerance: int = 300,
        password: Optional[bytes] = None,
        hide_user_agent_version: bool = False,
    ):
        """
        Initialize TACRecipient

        Args:
            domain: Domain of the recipient (required)
            private_key: Private key for decryption (required)
            cache_timeout: JWKS cache timeout in ms (default: 3600000)
            max_retries: Max retry attempts for network requests (default: 3)
            retry_delay: Retry delay in ms (default: 1000)
            clock_tolerance: Clock skew tolerance in seconds (default: 300 = 5 minutes)
            password: Password for encrypted private keys (default: None)
            hide_user_agent_version: If True, omit version details from User-Agent header (default: False)
        """
        if not domain:
            raise TACValidationError("domain is required in TACRecipient constructor", TACErrorCodes.DOMAIN_REQUIRED)
        if not private_key:
            raise TACValidationError(
                "privateKey is required in TACRecipient constructor", TACErrorCodes.PRIVATE_KEY_REQUIRED
            )

        self.domain = domain
        self._password = password
        self.set_private_key(private_key)  # This sets both private and public keys
        self.jwks_cache = JWKSCache(cache_timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.clock_tolerance = clock_tolerance
        self.hide_user_agent_version = hide_user_agent_version

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
                TACErrorCodes.UNSUPPORTED_KEY_TYPE,
            )

        # Always derive public key from private key
        self.public_key = self.private_key.public_key()

        # Store key type and algorithm
        self.key_type = get_key_type(self.private_key)
        self.encryption_algorithm = get_algorithm_for_key(self.private_key, "enc")

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

    async def process_tac_message(self, tac_message: Optional[str]) -> Dict[str, Any]:
        """
        Process TAC-Protocol message

        Args:
            tac_message: Base64-encoded TAC-Protocol message (from header or body)

        Returns:
            Processing result with valid, issuer, expires, data, recipients, errors
        """
        result = {
            "valid": False,
            "issuer": None,
            "expires": None,
            "jti": None,  # JWT ID for replay detection
            "data": None,
            "recipients": [],
            "errors": [],
        }

        if not tac_message:
            result["errors"].append("Missing TAC-Protocol message")
            return result

        # Check message size limit (100KB max to prevent DoS)
        MAX_MESSAGE_SIZE = 100 * 1024  # 100KB
        if len(tac_message) > MAX_MESSAGE_SIZE:
            result["errors"].append(f"Message too large: {len(tac_message)} bytes exceeds maximum of {MAX_MESSAGE_SIZE} bytes")
            return result

        # Decode base64 message (strictly required - raw JSON not accepted)
        # Check if input looks like raw JSON (not base64 encoded)
        trimmed = tac_message.strip()
        if trimmed.startswith("{") or trimmed.startswith("["):
            result["errors"].append("Invalid TAC-Protocol message: must be base64-encoded (raw JSON not accepted)")
            return result

        # Validate base64 format
        base64_regex = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
        if not base64_regex.match(tac_message):
            result["errors"].append("Invalid TAC-Protocol message: must be base64-encoded")
            return result

        try:
            decoded_message = base64.b64decode(tac_message).decode("utf-8")
        except Exception:
            result["errors"].append("Invalid TAC-Protocol message: must be base64-encoded")
            return result

        try:
            # Parse the multi-recipient message
            try:
                message = json.loads(decoded_message)
            except Exception:
                raise TACMessageError("Invalid TAC-Protocol message format", TACErrorCodes.INVALID_MESSAGE_FORMAT)

            # Validate message structure
            if "recipients" not in message or not isinstance(message["recipients"], list):
                raise TACMessageError("Invalid message format: missing recipients", TACErrorCodes.MISSING_RECIPIENTS)

            result["recipients"] = [r.get("kid", "unknown") for r in message["recipients"]]

            # Find our specific JWE
            our_recipient = None
            for recipient in message["recipients"]:
                if recipient.get("kid") == self.domain:
                    our_recipient = recipient
                    break

            if not our_recipient:
                raise TACMessageError(f"Not a recipient: {self.domain}", TACErrorCodes.NOT_A_RECIPIENT)

            if not self.private_key:
                raise TACValidationError("No private key available for decryption", TACErrorCodes.NO_PRIVATE_KEY)

            # Step 1: DECRYPT the JWE to get the signed JWT
            try:
                # Use the private key directly for decryption - jose library will handle the key type
                decrypted_jwt = jwe.decrypt(our_recipient["jwe"], self.private_key)
                signed_jwt = decrypted_jwt.decode("utf-8")
            except Exception as error:
                raise TACCryptoError(f"Decryption failed: {str(error)}", TACErrorCodes.DECRYPTION_FAILED)

            # Step 2: VERIFY the JWT signature using sender's public key
            # First, get the sender's domain and key ID from the JWT (without verification)
            try:
                unverified_header = jose.jwt.get_unverified_header(signed_jwt)
                unverified_payload = jose.jwt.get_unverified_claims(signed_jwt)
            except Exception as error:
                raise TACCryptoError(f"JWT decode failed: {str(error)}", TACErrorCodes.JWT_DECODE_FAILED)

            if "iss" not in unverified_payload:
                raise TACMessageError("JWT missing issuer (iss) claim", TACErrorCodes.JWT_MISSING_ISSUER)

            if unverified_payload.get("aud") != self.domain:
                raise TACMessageError(
                    f'JWT audience mismatch: expected {self.domain}, got {unverified_payload.get("aud")}',
                    TACErrorCodes.JWT_AUDIENCE_MISMATCH,
                )

            # Step 3: Fetch sender's public key and VERIFY the JWT signature
            agent_domain = unverified_payload["iss"]
            key_id = unverified_header.get("kid")  # Extract key ID for key selection

            try:
                jwks_keys = await self.fetch_jwks(agent_domain)
            except Exception as error:
                raise TACNetworkError(
                    f"Failed to fetch JWKS for {agent_domain}: {str(error)}", TACErrorCodes.JWKS_FETCH_FAILED
                )

            if not jwks_keys:
                raise TACNetworkError(
                    f"No public keys found for agent {agent_domain}", TACErrorCodes.NO_PUBLIC_KEYS_FOUND
                )

            # Find appropriate signing key to verify the JWT signature (using key ID if available)
            signing_key = find_signing_key(jwks_keys, key_id)
            if not signing_key:
                raise TACNetworkError("No suitable signing key found", TACErrorCodes.NO_SIGNING_KEY_FOUND)

            try:
                # VERIFY the JWT signature - this is the crucial security step!
                payload = jose.jwt.decode(
                    signed_jwt,
                    signing_key,
                    algorithms=[signing_key.get("alg", "RS256")],
                    audience=self.domain,
                    issuer=agent_domain,
                )
            except JWTError as error:
                raise TACCryptoError(
                    f"Signature verification failed: {str(error)}", TACErrorCodes.SIGNATURE_VERIFICATION_FAILED
                )

            # Additional manual validation for iat claim (not validated by jose by default)
            now = int(time.time())

            if payload.get("iat") and payload["iat"] > now + self.clock_tolerance:
                raise TACMessageError("JWT not yet valid (issued in the future)", TACErrorCodes.JWT_NOT_YET_VALID)

            # Extract data from verified payload
            result["valid"] = True
            result["issuer"] = payload.get("iss")
            result["expires"] = time.gmtime(payload.get("exp", 0)) if payload.get("exp") else None
            result["jti"] = payload.get("jti")  # JWT ID for replay detection

            # Get data specific to this recipient
            result["data"] = payload.get("data")

        except Exception as error:
            result["errors"].append(str(error))

        return result

    @staticmethod
    def inspect(tac_message: str) -> Dict[str, Any]:
        """
        Static method to inspect TAC-Protocol message without decryption

        Args:
            tac_message: Base64-encoded TAC-Protocol message

        Returns:
            Basic information about the message
        """
        try:
            import re

            # Check if input looks like raw JSON (not base64 encoded)
            trimmed = tac_message.strip()
            if trimmed.startswith("{") or trimmed.startswith("["):
                return {
                    "error": "Invalid TAC-Protocol message: must be base64-encoded (raw JSON not accepted)",
                    "version": None,
                    "recipients": [],
                    "expires": None,
                }

            # Validate base64 format
            base64_regex = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
            if not base64_regex.match(tac_message):
                return {
                    "error": "Invalid TAC-Protocol message: must be base64-encoded",
                    "version": None,
                    "recipients": [],
                    "expires": None,
                }

            # Decode base64 message
            decoded_message = base64.b64decode(tac_message).decode("utf-8")
            message = json.loads(decoded_message)

            return {
                "version": message.get("version", "2025-08-27"),
                "recipients": [r.get("kid", "unknown") for r in message.get("recipients", [])],
                "expires": None,  # Cannot get expiry without decryption
            }
        except Exception:
            return {"error": "Invalid TAC-Protocol message format", "version": None, "recipients": [], "expires": None}

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
            domain: Domain to clear cache for, or None to clear all
        """
        self.jwks_cache.clear(domain)
