"""
Trusted Agentic Commerce Protocol SDK for Python

Secure authentication and data encryption for AI agents
Implements JWT signing and JWE encryption for multi-recipient messages
"""

# Primary exports - recommended usage
from .sender import TACSender
from .recipient import TACRecipient

# Utility exports for advanced usage  
from .utils import (
    JWKSCache,
    fetch_jwks_with_retry,
    generate_key_id,
    find_encryption_key,
    find_signing_key,
    is_rsa_key,
    is_ec_key,
    get_key_type,
    get_algorithm_for_key,
    is_key_valid,
    public_key_to_jwk
)

__version__ = "0.1.0"
__author__ = "Forter"
__email__ = "ai@forter.com"

__all__ = [
    "TACSender",
    "TACRecipient", 
    "JWKSCache",
    "fetch_jwks_with_retry",
    "generate_key_id",
    "find_encryption_key",
    "find_signing_key",
    "is_rsa_key",
    "is_ec_key",
    "get_key_type",
    "get_algorithm_for_key",
    "is_key_valid",
    "public_key_to_jwk"
]
