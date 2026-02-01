#!/usr/bin/env python3
"""
Message Generation (Sender) Tests for TAC Protocol Python SDK

Tests JWT signing, encryption, multi-recipient messaging.
"""

import asyncio
import base64
import json
import os
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACNetworkError, TACValidationError
from recipient import TACRecipient
from sender import TACSender


class TestBasicSenderFunctionality(unittest.TestCase):
    """Test basic sender functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.private_key)

    def test_sender_initialization(self):
        """Test sender initialization"""
        self.assertEqual(self.sender.domain, "agent.com")
        self.assertIsNotNone(self.sender.private_key)
        self.assertIsNotNone(self.sender.public_key)

    def test_invalid_domain(self):
        """Test invalid domain handling"""
        with self.assertRaises(TACValidationError):
            TACSender(domain="", private_key=self.private_key)

        with self.assertRaises(TACValidationError):
            TACSender(domain=None, private_key=self.private_key)

    def test_invalid_private_key(self):
        """Test invalid private key handling"""
        with self.assertRaises(TACValidationError):
            TACSender(domain="test.com", private_key=None)

    def test_key_id_generation(self):
        """Test key ID generation"""
        key_id = self.sender.generate_key_id()
        self.assertIsInstance(key_id, str)
        self.assertGreater(len(key_id), 0)

        # Should be consistent
        key_id2 = self.sender.generate_key_id()
        self.assertEqual(key_id, key_id2)

    def test_public_jwk_export(self):
        """Test public key JWK export"""

        async def run_test():
            jwk = await self.sender.get_public_jwk()

            self.assertIn("kty", jwk)
            self.assertIn("kid", jwk)
            self.assertIn("alg", jwk)

            self.assertEqual(jwk["kty"], "RSA")
            self.assertIn("n", jwk)
            self.assertIn("e", jwk)
            self.assertEqual(jwk["alg"], "RS256")

        asyncio.run(run_test())


class TestRecipientDataManagement(unittest.TestCase):
    """Test recipient data management"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.private_key)

    def test_add_recipient_data(self):
        """Test adding recipient data"""
        test_data = {
            "user": {"email": {"address": "test@example.com"}, "id": "user123"},
            "session": {"ipAddress": "192.168.1.1", "userAgent": "Mozilla/5.0..."},
        }

        async def run_test():
            await self.sender.add_recipient_data("merchant.com", test_data)
            self.assertEqual(self.sender.recipient_data["merchant.com"], test_data)

        asyncio.run(run_test())

    def test_multiple_recipients(self):
        """Test adding multiple recipients"""
        data1 = {"user": {"id": "user1"}}
        data2 = {"user": {"id": "user2"}}

        async def run_test():
            await self.sender.add_recipient_data("merchant1.com", data1)
            await self.sender.add_recipient_data("merchant2.com", data2)

            self.assertEqual(len(self.sender.recipient_data), 2)
            self.assertEqual(self.sender.recipient_data["merchant1.com"], data1)
            self.assertEqual(self.sender.recipient_data["merchant2.com"], data2)

        asyncio.run(run_test())

    def test_update_recipient_data(self):
        """Test updating existing recipient data"""
        initial_data = {"user": {"id": "initial"}}
        updated_data = {"user": {"id": "updated"}}

        async def run_test():
            await self.sender.add_recipient_data("merchant.com", initial_data)
            self.assertEqual(self.sender.recipient_data["merchant.com"], initial_data)

            await self.sender.add_recipient_data("merchant.com", updated_data)
            self.assertEqual(self.sender.recipient_data["merchant.com"], updated_data)

        asyncio.run(run_test())

    def test_clear_recipient_data(self):
        """Test clearing recipient data"""
        test_data = {"user": {"id": "test"}}

        async def run_test():
            await self.sender.add_recipient_data("merchant.com", test_data)
            self.assertEqual(len(self.sender.recipient_data), 1)

            self.sender.clear_recipient_data()
            self.assertEqual(len(self.sender.recipient_data), 0)

        asyncio.run(run_test())

    def test_set_recipients_data(self):
        """Test setting all recipient data at once"""
        initial_data = {"test.com": {"user": {"id": "test"}}}
        new_data = {"merchant1.com": {"user": {"id": "user1"}}, "merchant2.com": {"user": {"id": "user2"}}}

        async def run_test():
            await self.sender.add_recipient_data("test.com", initial_data["test.com"])
            self.assertEqual(len(self.sender.recipient_data), 1)

            self.sender.set_recipients_data(new_data)
            self.assertEqual(len(self.sender.recipient_data), 2)
            self.assertNotIn("test.com", self.sender.recipient_data)
            self.assertIn("merchant1.com", self.sender.recipient_data)
            self.assertIn("merchant2.com", self.sender.recipient_data)

        asyncio.run(run_test())


class TestMessageGeneration(unittest.TestCase):
    """Test TAC message generation"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.private_key)

        # Create recipient keys for testing
        self.recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient = TACRecipient(domain="merchant.com", private_key=self.recipient_private_key)

    @patch.object(TACSender, "fetch_jwks")
    def test_generate_tac_message_single_recipient(self, mock_fetch_jwks):
        """Test generating TAC message for single recipient"""

        async def run_test():
            # Mock JWKS response
            recipient_jwk = await self.recipient.get_public_jwk()
            mock_fetch_jwks.return_value = [recipient_jwk]

            # Add recipient data
            test_data = {"user": {"email": {"address": "test@example.com"}, "id": "user123"}}
            await self.sender.add_recipient_data("merchant.com", test_data)

            # Generate message
            message = await self.sender.generate_tac_message()

            # Verify message structure
            self.assertIsInstance(message, str)

            # Decode and verify base64
            decoded = base64.b64decode(message)
            message_data = json.loads(decoded.decode("utf-8"))

            self.assertIn("version", message_data)
            self.assertIn("recipients", message_data)

            # Should have one recipient
            self.assertEqual(len(message_data["recipients"]), 1)
            recipient = message_data["recipients"][0]
            self.assertIn("kid", recipient)
            self.assertIn("jwe", recipient)

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    def test_generate_tac_message_multiple_recipients(self, mock_fetch_jwks):
        """Test generating TAC message for multiple recipients"""

        async def run_test():
            # Create second recipient
            recipient2_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            recipient2 = TACRecipient(domain="forter.com", private_key=recipient2_private_key)

            # Mock JWKS responses
            recipient1_jwk = await self.recipient.get_public_jwk()
            recipient2_jwk = await recipient2.get_public_jwk()

            def mock_fetch_side_effect(domain):
                if domain == "merchant.com":
                    return [recipient1_jwk]
                elif domain == "forter.com":
                    return [recipient2_jwk]
                return []

            mock_fetch_jwks.side_effect = mock_fetch_side_effect

            # Add recipient data
            await self.sender.add_recipient_data("merchant.com", {"user": {"id": "user1"}})
            await self.sender.add_recipient_data("forter.com", {"user": {"id": "user2"}})

            # Generate message
            message = await self.sender.generate_tac_message()

            # Decode and verify
            decoded = base64.b64decode(message)
            message_data = json.loads(decoded.decode("utf-8"))

            # Should have two recipients
            self.assertEqual(len(message_data["recipients"]), 2)

            # Verify each recipient has required fields
            for recipient in message_data["recipients"]:
                self.assertIn("kid", recipient)
                self.assertIn("jwe", recipient)

        asyncio.run(run_test())

    def test_generate_tac_message_no_recipients(self):
        """Test generating TAC message with no recipients fails"""

        async def run_test():
            with self.assertRaises(TACValidationError):
                await self.sender.generate_tac_message()

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    def test_generate_tac_message_jwks_fetch_failure(self, mock_fetch_jwks):
        """Test handling of JWKS fetch failure"""
        mock_fetch_jwks.side_effect = TACNetworkError("Failed to fetch JWKS")

        async def run_test():
            await self.sender.add_recipient_data("merchant.com", {"user": {"id": "test"}})

            with self.assertRaises(TACNetworkError):
                await self.sender.generate_tac_message()

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    def test_generate_tac_message_empty_jwks(self, mock_fetch_jwks):
        """Test handling of empty JWKS response"""
        mock_fetch_jwks.return_value = []

        async def run_test():
            await self.sender.add_recipient_data("merchant.com", {"user": {"id": "test"}})

            with self.assertRaises(TACNetworkError):
                await self.sender.generate_tac_message()

        asyncio.run(run_test())


class TestMessageIntegrity(unittest.TestCase):
    """Test message integrity and verification"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.private_key)

        self.recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient = TACRecipient(domain="merchant.com", private_key=self.recipient_private_key)

    @patch.object(TACSender, "fetch_jwks")
    @patch.object(TACRecipient, "fetch_jwks")
    def test_end_to_end_message_flow(self, mock_recipient_fetch, mock_sender_fetch):
        """Test complete end-to-end message flow"""

        async def run_test():
            # Set up mocks
            recipient_jwk = await self.recipient.get_public_jwk()
            sender_jwk = await self.sender.get_public_jwk()

            mock_sender_fetch.return_value = [recipient_jwk]
            mock_recipient_fetch.return_value = [sender_jwk]

            # Test data
            test_data = {
                "user": {"email": {"address": "test@example.com"}, "id": "user123"},
                "session": {"ipAddress": "192.168.1.1"},
            }

            # Generate message
            await self.sender.add_recipient_data("merchant.com", test_data)
            message = await self.sender.generate_tac_message()

            # Process message
            result = await self.recipient.process_tac_message(message)

            # Verify result
            self.assertTrue(result["valid"])
            self.assertEqual(result["issuer"], "agent.com")
            self.assertIsNotNone(result["data"])
            self.assertEqual(result["data"]["user"]["id"], "user123")
            self.assertEqual(result["data"]["user"]["email"]["address"], "test@example.com")

        asyncio.run(run_test())

    def test_message_structure_version(self):
        """Test that message includes correct version"""

        async def run_test():
            with patch.object(self.sender, "fetch_jwks") as mock_fetch:
                recipient_jwk = await self.recipient.get_public_jwk()
                mock_fetch.return_value = [recipient_jwk]

                await self.sender.add_recipient_data("merchant.com", {"test": "data"})
                message = await self.sender.generate_tac_message()

                decoded = base64.b64decode(message)
                message_data = json.loads(decoded.decode("utf-8"))

                self.assertIn("version", message_data)
                self.assertEqual(message_data["version"], "2025-08-27")

        asyncio.run(run_test())

    def test_message_jwe_structure(self):
        """Test that message includes valid JWE structure"""

        async def run_test():
            with patch.object(self.sender, "fetch_jwks") as mock_fetch:
                recipient_jwk = await self.recipient.get_public_jwk()
                mock_fetch.return_value = [recipient_jwk]

                await self.sender.add_recipient_data("merchant.com", {"test": "data"})
                message = await self.sender.generate_tac_message()

                decoded = base64.b64decode(message)
                message_data = json.loads(decoded.decode("utf-8"))

                self.assertIn("recipients", message_data)
                self.assertEqual(len(message_data["recipients"]), 1)

                recipient = message_data["recipients"][0]
                self.assertIn("jwe", recipient)

                # JWE should be in format: header.encrypted_key.iv.ciphertext.tag
                jwe_parts = recipient["jwe"].split(".")
                self.assertEqual(len(jwe_parts), 5)

        asyncio.run(run_test())


class TestErrorHandling(unittest.TestCase):
    """Test error handling in sender"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.private_key)

    def test_invalid_recipient_domain(self):
        """Test handling of invalid recipient domain"""

        async def run_test():
            with self.assertRaises(TACValidationError):
                await self.sender.add_recipient_data("", {"test": "data"})

            with self.assertRaises(TACValidationError):
                await self.sender.add_recipient_data(None, {"test": "data"})

        asyncio.run(run_test())

    def test_invalid_recipient_data(self):
        """Test handling of invalid recipient data"""

        async def run_test():
            # None data should be rejected
            with self.assertRaises(TACValidationError):
                await self.sender.add_recipient_data("merchant.com", None)

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    def test_encryption_failure_handling(self, mock_fetch_jwks):
        """Test handling of encryption failures"""
        # Mock invalid JWK that would cause encryption to fail
        invalid_jwk = {"kty": "RSA", "kid": "invalid-key", "n": "invalid", "e": "AQAB"}  # Invalid modulus
        mock_fetch_jwks.return_value = [invalid_jwk]

        async def run_test():
            await self.sender.add_recipient_data("merchant.com", {"test": "data"})

            with self.assertRaises(Exception):  # Should raise some encryption-related error
                await self.sender.generate_tac_message()

        asyncio.run(run_test())

    def test_large_payload_handling(self):
        """Test handling of large payloads"""
        large_data = {"user": {"metadata": "x" * 10000}}  # Large string

        async def run_test():
            with patch.object(self.sender, "fetch_jwks") as mock_fetch:
                # Create valid recipient key
                recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                recipient = TACRecipient(domain="merchant.com", private_key=recipient_private_key)
                recipient_jwk = await recipient.get_public_jwk()
                mock_fetch.return_value = [recipient_jwk]

                # Should handle large payloads
                await self.sender.add_recipient_data("merchant.com", large_data)
                message = await self.sender.generate_tac_message()

                self.assertIsInstance(message, str)
                self.assertGreater(len(message), 1000)  # Should be substantial

        asyncio.run(run_test())


class TestJWTIDClaim(unittest.TestCase):
    """Test JWT ID (jti) claim functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.private_key)

    def test_jti_included_in_jwt(self):
        """Test that jti claim is included in generated JWT"""

        async def run_test():
            # Create recipient
            recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            recipient = TACRecipient(domain="merchant.com", private_key=recipient_private_key)

            # Mock JWKS fetch for both sender and recipient
            with patch.object(self.sender, "fetch_jwks") as mock_sender_fetch:
                recipient_jwk = await recipient.get_public_jwk()
                mock_sender_fetch.return_value = [recipient_jwk]

                await self.sender.add_recipient_data("merchant.com", {"test": "data"})
                message = await self.sender.generate_tac_message()

                # Decode and verify jti is present
                decoded = json.loads(base64.b64decode(message).decode("utf-8"))
                self.assertIn("recipients", decoded)

                # Process the message to get the JWT payload
                with patch.object(recipient, "fetch_jwks") as mock_recipient_fetch:
                    sender_jwk = await self.sender.get_public_jwk()
                    mock_recipient_fetch.return_value = [sender_jwk]

                    result = await recipient.process_tac_message(message)

                    self.assertTrue(result["valid"])
                    self.assertIn("jti", result)
                    self.assertIsNotNone(result["jti"])
                    # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                    import re

                    uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                    self.assertRegex(result["jti"], uuid_pattern)

        asyncio.run(run_test())

    def test_unique_jti_per_message(self):
        """Test that each message gets a unique jti"""

        async def run_test():
            recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            recipient = TACRecipient(domain="merchant.com", private_key=recipient_private_key)

            with patch.object(self.sender, "fetch_jwks") as mock_sender_fetch:
                recipient_jwk = await recipient.get_public_jwk()
                mock_sender_fetch.return_value = [recipient_jwk]

                # Generate first message
                await self.sender.add_recipient_data("merchant.com", {"test": "data1"})
                message1 = await self.sender.generate_tac_message()

                # Generate second message
                self.sender.clear_recipient_data()
                await self.sender.add_recipient_data("merchant.com", {"test": "data2"})
                message2 = await self.sender.generate_tac_message()

                # Get jti from both messages
                with patch.object(recipient, "fetch_jwks") as mock_recipient_fetch:
                    sender_jwk = await self.sender.get_public_jwk()
                    mock_recipient_fetch.return_value = [sender_jwk]

                    result1 = await recipient.process_tac_message(message1)
                    result2 = await recipient.process_tac_message(message2)

                    self.assertTrue(result1["valid"])
                    self.assertTrue(result2["valid"])
                    self.assertNotEqual(result1["jti"], result2["jti"])

        asyncio.run(run_test())


class TestPasswordProtectedKeys(unittest.TestCase):
    """Test password-protected private key support"""

    def test_password_parameter_accepted(self):
        """Test that password parameter is accepted in constructor"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Should accept password parameter without error
        sender = TACSender(
            domain="test.com",
            private_key=private_key,
            password=b"test_password"  # Password won't be used for unencrypted key
        )
        self.assertIsNotNone(sender)

    def test_encrypted_pem_key_loading(self):
        """Test loading encrypted PEM key with password"""
        from cryptography.hazmat.primitives import serialization

        # Generate a key and encrypt it with a password
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        password = b"test_password_123"

        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        # Should be able to load with correct password
        sender = TACSender(domain="test.com", private_key=encrypted_pem.decode(), password=password)
        self.assertIsNotNone(sender.private_key)
        self.assertIsNotNone(sender.public_key)

    def test_encrypted_pem_wrong_password_fails(self):
        """Test that wrong password fails to load encrypted key"""
        from cryptography.hazmat.primitives import serialization
        from errors import TACCryptoError

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        password = b"correct_password"

        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        # Should fail with wrong password
        with self.assertRaises(TACCryptoError):
            TACSender(domain="test.com", private_key=encrypted_pem.decode(), password=b"wrong_password")

    def test_encrypted_pem_missing_password_fails(self):
        """Test that encrypted key without password fails"""
        from cryptography.hazmat.primitives import serialization
        from errors import TACCryptoError

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        password = b"test_password"

        encrypted_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        # Should fail without password
        with self.assertRaises(TACCryptoError):
            TACSender(domain="test.com", private_key=encrypted_pem.decode())


if __name__ == "__main__":
    unittest.main()
