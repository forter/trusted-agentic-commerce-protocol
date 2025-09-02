"""
Trusted Agentic Commerce Protocol Python SDK

Secure authentication and data encryption for AI agents
Implements JWS+JWE for signing and encryption with multi-recipient messages
"""

# Error exports for better error handling
from .errors import (
    TACCryptoError,
    TACError,
    TACErrorCodes,
    TACMessageError,
    TACNetworkError,
    TACValidationError,
)
from .recipient import TACRecipient

# Primary exports - recommended usage
from .sender import TACSender

# Utility exports for advanced usage
from .utils import (
    JWKSCache,
    fetch_jwks_with_retry,
    find_encryption_key,
    find_signing_key,
    get_algorithm_for_key,
    get_key_type,
    get_user_agent,
    public_key_to_jwk,
)

# Version exports
from .version import SCHEMA_VERSION, SDK_LANGUAGE, SDK_VERSION

__version__ = SDK_VERSION
__all__ = [
    # Primary classes
    "TACSender",
    "TACRecipient",
    # Error classes
    "TACError",
    "TACValidationError",
    "TACNetworkError",
    "TACCryptoError",
    "TACMessageError",
    "TACErrorCodes",
    # Version constants
    "SCHEMA_VERSION",
    "SDK_VERSION",
    "SDK_LANGUAGE",
    # Utility functions
    "JWKSCache",
    "fetch_jwks_with_retry",
    "find_encryption_key",
    "find_signing_key",
    "get_key_type",
    "get_algorithm_for_key",
    "public_key_to_jwk",
    "get_user_agent",
]
