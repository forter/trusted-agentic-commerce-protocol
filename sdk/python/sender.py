"""
TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
Handles JWT signing and multi-recipient JWE encryption
"""

import json
import time
import base64
from typing import Dict, List, Optional, Any, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from jose import jwt, jwe, jwk
from jose.exceptions import JWTError, JWEError

try:
    from .utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_encryption_key,
        generate_key_id,
        is_rsa_key,
        is_ec_key,
        get_key_type,
        get_algorithm_for_key,
        public_key_to_jwk
    )
    from .version import get_sender_user_agent
except ImportError:
    from utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_encryption_key,
        generate_key_id,
        is_rsa_key,
        is_ec_key,
        get_key_type,
        get_algorithm_for_key,
        public_key_to_jwk
    )
    from version import get_sender_user_agent


class TACSender:
    """
    TACSender - Implements the sender side of the Trusted Agentic Commerce Protocol
    Handles JWT signing and multi-recipient JWE encryption
    """
    
    def __init__(self, domain: str, private_key: Union[str, Any], ttl: int = 3600, 
                 cache_timeout: int = 3600000, max_retries: int = 3, retry_delay: int = 1000):
        """
        Initialize TACSender
        
        Args:
            domain: Domain of the agent (required)
            private_key: Private key for signing - RSA or EC (required)
            ttl: JWT expiration time in seconds (default: 3600)
            cache_timeout: JWKS cache timeout in ms (default: 3600000)
            max_retries: Max retry attempts for network requests (default: 3)
            retry_delay: Retry delay in ms (default: 1000)
        """
        if not domain:
            raise ValueError('domain is required in TACSender constructor')
        if not private_key:
            raise ValueError('privateKey is required in TACSender constructor')
        
        self.domain = domain
        self.set_private_key(private_key)
        self.ttl = ttl
        self.jwks_cache = JWKSCache(cache_timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.recipient_data: Dict[str, Dict] = {}
    
    def set_private_key(self, private_key: Union[str, Any]):
        """
        Set private key and automatically derive public key
        
        Args:
            private_key: Private key object or PEM string (RSA or EC)
        """
        if isinstance(private_key, str):
            self.private_key = serialization.load_pem_private_key(
                private_key.encode(), password=None
            )
        else:
            self.private_key = private_key

        # Verify it's a supported key type
        if not (is_rsa_key(self.private_key) or is_ec_key(self.private_key)):
            raise ValueError('TAC Protocol requires RSA or EC (P-256/384/521) keys')

        # Derive public key from private key
        self.public_key = self.private_key.public_key()
        
        # Store key type and algorithm
        self.key_type = get_key_type(self.private_key)
        self.signing_algorithm = get_algorithm_for_key(self.private_key, 'sig')
    
    def generate_key_id(self) -> str:
        """
        Generate key ID from public key
        
        Returns:
            Base64url encoded SHA-256 hash of public key
        """
        if not self.public_key:
            raise ValueError('No public key available. Load or set keys first.')
        
        return generate_key_id(self.public_key)
    
    def add_recipient_data(self, domain: str, data: Dict[str, Any]):
        """
        Add data to be encrypted for a specific recipient
        
        Args:
            domain: Recipient domain
            data: Data to encrypt for this recipient
        """
        self.recipient_data[domain] = data
    
    def set_recipients_data(self, recipient_data: Dict[str, Dict[str, Any]]):
        """
        Set all recipients data, clearing any existing data first
        
        Args:
            recipient_data: Dictionary mapping domain to data
        """
        self.recipient_data = recipient_data.copy()
    
    def clear_recipient_data(self):
        """Clear all recipient data"""
        self.recipient_data = {}
    
    async def generate_tac_message(self) -> str:
        """
        Generate TAC-Protocol message with signed JWT and encrypted data
        
        Returns:
            Base64-encoded TAC-Protocol message (ready for HTTP headers or body)
        """
        if not self.recipient_data:
            raise ValueError('No recipient data added. Use add_recipient_data() first.')
        
        if not self.private_key:
            raise ValueError('No private key available for signing')
        
        # Fetch recipient public keys
        recipient_public_keys = {}
        for domain in self.recipient_data.keys():
            keys = await self.fetch_jwks(domain)
            encryption_key = find_encryption_key(keys)
            if not encryption_key:
                raise ValueError(f'No encryption key found for {domain}')
            recipient_public_keys[domain] = encryption_key
        
        # Create individual JWE for each recipient with their specific data
        now = int(time.time())
        recipient_jwes = []

        for domain, jwk_dict in recipient_public_keys.items():
            # Create JWT payload with only this recipient's data
            payload = {
                'iss': self.domain,
                'exp': now + self.ttl,
                'iat': now,
                'aud': domain,  # Audience claim for this specific recipient
                'data': self.recipient_data[domain]  # Only this recipient's data
            }

            # Sign the JWT using appropriate algorithm based on key type
            if is_rsa_key(self.private_key):
                private_key_jwk = jwk.RSAKey(key=self.private_key, algorithm=self.signing_algorithm).to_dict()
            elif is_ec_key(self.private_key):
                private_key_jwk = jwk.ECKey(key=self.private_key, algorithm=self.signing_algorithm).to_dict()
            else:  # OKP key
                # For OKP keys, we need to use the raw key material
                # python-jose doesn't directly support OKP, so we'll handle it specially
                private_key_jwk = self._create_okp_jwk()

            signed_jwt = jwt.encode(
                payload, 
                private_key_jwk, 
                algorithm=self.signing_algorithm
            )

            # Convert JWK to key object for python-jose based on key type
            kty = jwk_dict.get('kty')
            alg = jwk_dict.get('alg', 'RSA-OAEP-256' if kty == 'RSA' else 'ECDH-ES+A256KW')
            
            if kty == 'RSA':
                recipient_key = jwk.RSAKey(jwk_dict, algorithm=alg)
            elif kty == 'EC':
                recipient_key = jwk.ECKey(jwk_dict, algorithm=alg)
            else:  # OKP
                # For OKP keys, we'll use a workaround with EC support
                recipient_key = jwk_dict
            
            # Encrypt the signed JWT for this recipient
            if isinstance(recipient_key, dict):
                # Direct JWK dict for unsupported key types
                encrypted_jwt = jwe.encrypt(
                    signed_jwt.encode('utf-8'),
                    recipient_key,
                    algorithm=alg,
                    encryption='A256GCM'
                )
            else:
                encrypted_jwt = jwe.encrypt(
                    signed_jwt.encode('utf-8'),
                    recipient_key.to_dict(),
                    algorithm=alg,
                    encryption='A256GCM'
                )

            recipient_jwes.append({
                'kid': domain,
                'jwe': encrypted_jwt
            })

        # Create multi-recipient container
        multi_recipient_message = {
            'version': '2025-08-27',
            'recipients': recipient_jwes
        }

        message_json = json.dumps(multi_recipient_message)
        return base64.b64encode(message_json.encode('utf-8')).decode('utf-8')
    
    async def fetch_jwks(self, domain: str, force_refresh: bool = False) -> List[Dict]:
        """
        Fetch JWKS for a domain with caching
        
        Args:
            domain: Domain to fetch JWKS for
            force_refresh: Force refresh cache
            
        Returns:
            List of JWK keys
        """
        if not force_refresh:
            cached_keys = self.jwks_cache.get(domain)
            if cached_keys:
                return cached_keys
        
        # Fetch from well-known endpoint
        jwks_url = f'https://{domain}/.well-known/jwks.json'
        keys = await fetch_jwks_with_retry(
            jwks_url, 
            self.max_retries, 
            self.retry_delay, 
            user_agent=get_sender_user_agent()
        )
        
        # Cache the keys
        self.jwks_cache.set(domain, keys)
        
        return keys
    
    def clear_cache(self, domain: Optional[str] = None):
        """
        Clear JWKS cache
        
        Args:
            domain: Domain to clear cache for, or None to clear all
        """
        self.jwks_cache.clear(domain)
    
    def get_public_jwk(self) -> Dict[str, Any]:
        """
        Get public key as JWK for publishing (bidirectional use)
        
        Returns:
            JWK representation of the public key
        """
        return public_key_to_jwk(self.public_key, self.generate_key_id())
