"""
TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
Handles TAC-Protocol message verification and decryption
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
        find_signing_key,
        generate_key_id,
        is_rsa_key,
        is_ec_key,
        get_key_type,
        get_algorithm_for_key,
        public_key_to_jwk
    )
    from .version import get_recipient_user_agent
except ImportError:
    from utils import (
        JWKSCache,
        fetch_jwks_with_retry,
        find_signing_key,
        generate_key_id,
        is_rsa_key,
        is_ec_key,
        get_key_type,
        get_algorithm_for_key,
        public_key_to_jwk
    )
    from version import get_recipient_user_agent


class TACRecipient:
    """
    TACRecipient - Implements the recipient side of the Trusted Agentic Commerce Protocol
    Handles TAC-Protocol message verification and decryption
    """
    
    def __init__(self, domain: str, private_key: Union[str, Any], cache_timeout: int = 3600000, 
                 max_retries: int = 3, retry_delay: int = 1000):
        """
        Initialize TACRecipient
        
        Args:
            domain: Domain of the recipient (required)
            private_key: Private key for decryption - RSA or EC (required)
            cache_timeout: JWKS cache timeout in ms (default: 3600000)
            max_retries: Max retry attempts for network requests (default: 3)
            retry_delay: Retry delay in ms (default: 1000)
        """
        if not domain:
            raise ValueError('domain is required in TACRecipient constructor')
        if not private_key:
            raise ValueError('privateKey is required in TACRecipient constructor')
        
        self.domain = domain
        self.set_private_key(private_key)
        self.jwks_cache = JWKSCache(cache_timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
    
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
        self.encryption_algorithm = get_algorithm_for_key(self.private_key, 'enc')
    
    def generate_key_id(self) -> str:
        """
        Generate key ID from public key
        
        Returns:
            Base64url encoded SHA-256 hash of public key
        """
        if not self.public_key:
            raise ValueError('No public key available. Load or set keys first.')
        
        return generate_key_id(self.public_key)
    
    async def process_tac_message(self, tac_message: Optional[str]) -> Dict[str, Any]:
        """
        Process TAC-Protocol message
        
        Args:
            tac_message: Base64-encoded TAC-Protocol message (from header or body)
            
        Returns:
            Processing result with valid, issuer, expires, data, recipients, errors
        """
        result = {
            'valid': False,
            'issuer': None,
            'expires': None,
            'data': None,
            'recipients': [],
            'errors': [],
        }

        if not tac_message:
            result['errors'].append('Missing TAC-Protocol message')
            return result

        # Decode base64 message
        try:
            # Try to decode as base64 first
            decoded_message = base64.b64decode(tac_message).decode('utf-8')
            # Validate it's valid JSON
            json.loads(decoded_message)
        except Exception:
            # If base64 decode fails, assume it's already JSON (backward compatibility)
            decoded_message = tac_message

        try:
            # Parse the multi-recipient message
            try:
                message = json.loads(decoded_message)
            except Exception:
                result['errors'].append('Invalid TAC-Protocol message format')
                return result

            # Validate message structure
            if 'recipients' not in message or not isinstance(message['recipients'], list):
                result['errors'].append('Invalid message format: missing recipients')
                return result

            result['recipients'] = [r.get('kid', 'unknown') for r in message['recipients']]

            # Find our specific JWE
            our_recipient = None
            for recipient in message['recipients']:
                if recipient.get('kid') == self.domain:
                    our_recipient = recipient
                    break
            
            if not our_recipient:
                result['errors'].append(f'Not a recipient: {self.domain}')
                return result

            if not self.private_key:
                result['errors'].append('No private key available for decryption')
                return result

            # Decrypt our specific JWE to get the signed JWT
            private_key_jwk = jwk.RSAKey(key=self.private_key, algorithm='RSA-OAEP-256').to_dict()
            
            try:
                decrypted_jwt = jwe.decrypt(our_recipient['jwe'], private_key_jwk)
                jwt_string = decrypted_jwt.decode('utf-8')
            except Exception as e:
                result['errors'].append(f'JWE decryption failed: {str(e)}')
                return result

            # Get the issuer domain from the JWT to fetch their public key
            try:
                unverified_payload = jwt.get_unverified_claims(jwt_string)
            except Exception:
                result['errors'].append('Invalid JWT format')
                return result
            
            if 'iss' not in unverified_payload:
                result['errors'].append('JWT missing issuer (iss) claim')
                return result

            # Verify the audience claim
            if unverified_payload.get('aud') != self.domain:
                result['errors'].append(f'JWT audience mismatch: expected {self.domain}, got {unverified_payload.get("aud")}')
                return result

            # Fetch the agent's public key
            agent_domain = unverified_payload['iss']
            try:
                jwks_keys = await self.fetch_jwks(agent_domain)
            except Exception as e:
                result['errors'].append(f'Failed to fetch JWKS for {agent_domain}: {str(e)}')
                return result
            
            if not jwks_keys:
                result['errors'].append(f'No public keys found for agent {agent_domain}')
                return result

            # Find appropriate signing key and verify JWT using python-jose
            signing_key = find_signing_key(jwks_keys)
            if not signing_key:
                result['errors'].append('No suitable signing key found')
                return result
            
            try:
                # Verify JWT signature
                payload = jwt.decode(
                    jwt_string, 
                    signing_key, 
                    algorithms=['RS256']
                )
            except JWTError as e:
                result['errors'].append(f'JWT verification failed: {str(e)}')
                return result

            # Extract data from verified payload
            result['valid'] = True
            result['issuer'] = payload.get('iss')
            result['expires'] = time.gmtime(payload.get('exp', 0)) if payload.get('exp') else None
            
            # Get data specific to this recipient
            result['data'] = payload.get('data')

        except Exception as e:
            result['errors'].append(f'Processing error: {str(e)}')

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
            # Decode base64 message
            try:
                decoded_message = base64.b64decode(tac_message).decode('utf-8')
                json.loads(decoded_message)
            except Exception:
                decoded_message = tac_message
                
            jwe_data = json.loads(decoded_message)
            
            return {
                'version': jwe_data.get('version', '2025-08-27'),
                'recipients': [r.get('kid', 'unknown') for r in jwe_data.get('recipients', [])],
                'expires': None  # Cannot get expiry without decryption
            }
        except Exception:
            return {
                'error': 'Invalid TAC-Protocol message format',
                'recipients': []
            }
    
    def get_public_jwk(self) -> Dict[str, Any]:
        """
        Get public key as JWK for publishing (bidirectional use)
        
        Returns:
            JWK representation of the public key
        """
        return public_key_to_jwk(self.public_key, self.generate_key_id())
    
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
            user_agent=get_recipient_user_agent()
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