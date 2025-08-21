#!/usr/bin/env python3
"""
Tests for Trusted Agentic Commerce Protocol Python SDK
"""

import unittest
import json
import base64
import asyncio
from unittest.mock import AsyncMock, patch
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Import from local modules
from sender import TACSender
from recipient import TACRecipient
from utils import (
    JWKSCache,
    generate_key_id,
    find_encryption_key,
    find_signing_key,
    is_rsa_key,
    is_ec_key,
    get_key_type
)


def generate_rsa_key_pair():
    """Helper function to generate RSA key pairs for testing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ec_key_pair():
    """Helper function to generate EC key pairs for testing"""
    private_key = ec.generate_private_key(
        ec.SECP256R1()  # P-256 curve
    )
    public_key = private_key.public_key()
    return private_key, public_key




class TestTACSender(unittest.TestCase):
    """Test TACSender functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.private_key, self.public_key = generate_rsa_key_pair()
        self.sender = TACSender(domain='agent.example.com', private_key=self.private_key)
    
    def test_requires_domain_and_private_key(self):
        """Test that constructor requires domain and private key"""
        with self.assertRaises(ValueError):
            TACSender(domain='', private_key=self.private_key)
        
        with self.assertRaises(ValueError):
            TACSender(domain='test.com', private_key=None)
    
    def test_initialization_with_rsa_keys(self):
        """Test initialization with RSA keys"""
        self.assertEqual(self.sender.domain, 'agent.example.com')
        self.assertTrue(is_rsa_key(self.sender.private_key))
        self.assertTrue(is_rsa_key(self.sender.public_key))
    
    def test_initialization_with_ec_keys(self):
        """Test initialization with EC keys"""
        ec_private_key, ec_public_key = generate_ec_key_pair()
        sender = TACSender(domain='agent.example.com', private_key=ec_private_key)
        
        self.assertEqual(sender.domain, 'agent.example.com')
        self.assertTrue(is_ec_key(sender.private_key))
        self.assertTrue(is_ec_key(sender.public_key))
        self.assertEqual(get_key_type(sender.private_key), 'EC')
    
    
    def test_generates_consistent_key_ids(self):
        """Test that key IDs are generated consistently"""
        key_id1 = self.sender.generate_key_id()
        key_id2 = self.sender.generate_key_id()
        
        self.assertEqual(key_id1, key_id2)
        # Should be base64url format
        import re
        self.assertRegex(key_id1, r'^[A-Za-z0-9_-]+$')
    
    def test_add_recipient_data(self):
        """Test adding recipient data"""
        test_data = {
            'user': {'email': {'address': 'test@example.com'}}
        }
        
        self.sender.add_recipient_data('merchant.com', test_data)
        
        self.assertEqual(self.sender.recipient_data['merchant.com'], test_data)
    
    def test_set_recipients_data_clears_existing(self):
        """Test that setRecipientsData clears existing data"""
        # Add some initial data
        self.sender.add_recipient_data('old.com', {'test': 'data'})
        
        # Set new data (should clear old)
        new_data = {
            'merchant.com': {'user': {'email': {'address': 'test@example.com'}}},
            'forter.com': {'session': {'ipAddress': '1.2.3.4'}}
        }
        self.sender.set_recipients_data(new_data)
        
        self.assertEqual(len(self.sender.recipient_data), 2)
        self.assertIn('merchant.com', self.sender.recipient_data)
        self.assertIn('forter.com', self.sender.recipient_data)
        self.assertNotIn('old.com', self.sender.recipient_data)
    
    def test_clear_recipient_data(self):
        """Test clearing recipient data"""
        self.sender.add_recipient_data('test.com', {'data': 'test'})
        self.sender.clear_recipient_data()
        
        self.assertEqual(self.sender.recipient_data, {})
    
    def test_get_public_jwk_rsa(self):
        """Test exporting RSA public key as JWK"""
        jwk = self.sender.get_public_jwk()
        
        self.assertEqual(jwk['kty'], 'RSA')
        self.assertEqual(jwk['alg'], 'RS256')
        self.assertIn('kid', jwk)
        self.assertIn('n', jwk)
        self.assertIn('e', jwk)
    
    def test_get_public_jwk_ec(self):
        """Test exporting EC public key as JWK"""
        ec_private_key, _ = generate_ec_key_pair()
        sender = TACSender(domain='agent.example.com', private_key=ec_private_key)
        jwk = sender.get_public_jwk()
        
        self.assertEqual(jwk['kty'], 'EC')
        self.assertEqual(jwk['alg'], 'ES256')
        self.assertEqual(jwk['crv'], 'P-256')
        self.assertIn('kid', jwk)
        self.assertIn('x', jwk)
        self.assertIn('y', jwk)
    
    
    def test_generate_tac_message_requires_recipient_data(self):
        """Test that generateTACMessage requires recipient data"""
        with self.assertRaises(ValueError):
            asyncio.run(self.sender.generate_tac_message())


class TestTACRecipient(unittest.TestCase):
    """Test TACRecipient functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.private_key, self.public_key = generate_rsa_key_pair()
        self.recipient = TACRecipient(domain='merchant.com', private_key=self.private_key)
    
    def test_requires_domain_and_private_key(self):
        """Test that constructor requires domain and private key"""
        with self.assertRaises(ValueError):
            TACRecipient(domain='', private_key=self.private_key)
        
        with self.assertRaises(ValueError):
            TACRecipient(domain='test.com', private_key=None)
    
    def test_initialization_with_rsa_keys(self):
        """Test initialization with RSA keys"""
        self.assertEqual(self.recipient.domain, 'merchant.com')
        self.assertTrue(is_rsa_key(self.recipient.private_key))
        self.assertTrue(is_rsa_key(self.recipient.public_key))
    
    def test_initialization_with_ec_keys(self):
        """Test initialization with EC keys"""
        ec_private_key, ec_public_key = generate_ec_key_pair()
        recipient = TACRecipient(domain='merchant.com', private_key=ec_private_key)
        
        self.assertEqual(recipient.domain, 'merchant.com')
        self.assertTrue(is_ec_key(recipient.private_key))
        self.assertTrue(is_ec_key(recipient.public_key))
    
    
    def test_get_public_jwk_for_encryption_rsa(self):
        """Test exporting RSA public key as encryption JWK"""
        jwk = self.recipient.get_public_jwk()
        
        self.assertEqual(jwk['kty'], 'RSA')
        self.assertEqual(jwk['alg'], 'RS256')
        self.assertIn('kid', jwk)
        self.assertIn('n', jwk)
        self.assertIn('e', jwk)
    
    def test_get_public_jwk_for_encryption_ec(self):
        """Test exporting EC public key as encryption JWK"""
        ec_private_key, _ = generate_ec_key_pair()
        recipient = TACRecipient(domain='merchant.com', private_key=ec_private_key)
        jwk = recipient.get_public_jwk()
        
        self.assertEqual(jwk['kty'], 'EC')
        self.assertEqual(jwk['alg'], 'ES256')
        self.assertIn('kid', jwk)
        self.assertIn('x', jwk)
        self.assertIn('y', jwk)
    
    
    def test_process_missing_tac_message(self):
        """Test processing missing TAC message"""
        result = asyncio.run(self.recipient.process_tac_message(None))
        
        self.assertFalse(result['valid'])
        self.assertIn('Missing TAC-Protocol message', result['errors'])
    
    def test_process_invalid_tac_message_format(self):
        """Test processing invalid TAC message format"""
        result = asyncio.run(self.recipient.process_tac_message('invalid-json'))
        
        self.assertFalse(result['valid'])
        self.assertTrue(any('Invalid TAC-Protocol message format' in error for error in result['errors']))
    
    def test_inspect_tac_message_without_decryption(self):
        """Test static inspect method"""
        mock_message = {
            'version': '2025-08-21',
            'recipients': [
                {'kid': 'merchant.com', 'jwe': 'encrypted_data_for_merchant'},
                {'kid': 'forter.com', 'jwe': 'encrypted_data_for_forter'}
            ]
        }
        
        mock_message_string = json.dumps(mock_message)
        base64_mock_message = base64.b64encode(mock_message_string.encode('utf-8')).decode('utf-8')
        info = TACRecipient.inspect(base64_mock_message)
        
        self.assertEqual(info['version'], '2025-08-21')
        self.assertEqual(info['recipients'], ['merchant.com', 'forter.com'])


class TestUtilityFunctions(unittest.TestCase):
    """Test utility functions"""
    
    def test_jwks_cache(self):
        """Test JWKS cache functionality"""
        cache = JWKSCache(timeout=1000)  # 1 second timeout
        keys = [{'kty': 'RSA', 'kid': 'test'}]
        
        cache.set('test.com', keys)
        self.assertEqual(cache.get('test.com'), keys)
        
        cache.clear('test.com')
        self.assertIsNone(cache.get('test.com'))
    
    def test_find_rsa_encryption_keys(self):
        """Test finding RSA encryption keys"""
        keys = [
            {'kty': 'EC', 'use': 'sig', 'alg': 'ES256', 'kid': 'ec-key'},
            {'kty': 'RSA', 'use': 'enc', 'alg': 'RSA-OAEP-256', 'kid': 'rsa-enc', 'n': 'test', 'e': 'AQAB'},
            {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'rsa-sig'}
        ]
        
        enc_key = find_encryption_key(keys)
        self.assertIsNotNone(enc_key)
        self.assertEqual(enc_key['kid'], 'rsa-enc')
        self.assertEqual(enc_key['use'], 'enc')
        self.assertEqual(enc_key['kty'], 'RSA')
    
    def test_find_rsa_signing_keys(self):
        """Test finding RSA signing keys"""
        keys = [
            {'kty': 'EC', 'use': 'sig', 'alg': 'ES256', 'kid': 'ec-key'},
            {'kty': 'RSA', 'use': 'enc', 'alg': 'RSA-OAEP-256', 'kid': 'rsa-enc'},
            {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'rsa-sig', 'n': 'test', 'e': 'AQAB'}
        ]
        
        sig_key = find_signing_key(keys, 'rsa-sig')
        self.assertIsNotNone(sig_key)
        self.assertEqual(sig_key['kid'], 'rsa-sig')
        self.assertEqual(sig_key['use'], 'sig')
        self.assertEqual(sig_key['kty'], 'RSA')
    
    def test_supports_rsa_and_ec_keys(self):
        """Test that key finding functions support RSA and EC keys"""
        keys = [
            {'kty': 'EC', 'use': 'sig', 'alg': 'ES256', 'kid': 'ec-key'},
            {'kty': 'EC', 'use': 'enc', 'alg': 'ECDH-ES+A256KW', 'kid': 'ec-enc-key'},
            {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'rsa-key'},
            {'kty': 'OKP', 'use': 'sig', 'alg': 'EdDSA', 'kid': 'unsupported-key'}  # Unsupported
        ]
        
        # Should find EC encryption key
        enc_key = find_encryption_key(keys)
        self.assertIsNotNone(enc_key)
        self.assertEqual(enc_key['kty'], 'EC')
        
        # Should find EC signing key (first in list)
        sig_key = find_signing_key(keys)
        self.assertIsNotNone(sig_key)
        self.assertEqual(sig_key['kty'], 'EC')


if __name__ == '__main__':
    # Configure asyncio for Windows compatibility
    import sys
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    unittest.main()