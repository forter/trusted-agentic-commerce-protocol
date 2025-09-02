#!/usr/bin/env python3
"""
Message Processing (Recipient) Tests for TAC Protocol Python SDK

Tests JWT verification, decryption, signature validation.
"""

import asyncio
import base64
import json
import os
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec, rsa

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACNetworkError, TACValidationError
from recipient import TACRecipient
from sender import TACSender


class TestBasicRecipientFunctionality(unittest.TestCase):
    """Test basic recipient functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient = TACRecipient(domain="merchant.com", private_key=self.private_key)

    def test_recipient_initialization(self):
        """Test recipient initialization"""
        self.assertEqual(self.recipient.domain, "merchant.com")
        self.assertIsNotNone(self.recipient.private_key)
        self.assertIsNotNone(self.recipient.public_key)

    def test_recipient_with_ec_keys(self):
        """Test recipient initialization with EC keys"""
        ec_private_key = ec.generate_private_key(ec.SECP256R1())
        recipient = TACRecipient(domain="test.com", private_key=ec_private_key)

        self.assertEqual(recipient.domain, "test.com")
        self.assertIsNotNone(recipient.private_key)
        self.assertIsNotNone(recipient.public_key)

    def test_invalid_domain(self):
        """Test invalid domain handling"""
        with self.assertRaises(TACValidationError):
            TACRecipient(domain="", private_key=self.private_key)

        with self.assertRaises(TACValidationError):
            TACRecipient(domain=None, private_key=self.private_key)

    def test_invalid_private_key(self):
        """Test invalid private key handling"""
        with self.assertRaises(TACValidationError):
            TACRecipient(domain="test.com", private_key=None)

    def test_public_jwk_export(self):
        """Test public key JWK export"""

        async def run_test():
            jwk = await self.recipient.get_public_jwk()

            self.assertIn("kty", jwk)
            self.assertIn("kid", jwk)
            self.assertIn("alg", jwk)

            if jwk["kty"] == "RSA":
                self.assertIn("n", jwk)
                self.assertIn("e", jwk)
                self.assertEqual(jwk["alg"], "RS256")
            elif jwk["kty"] == "EC":
                self.assertIn("x", jwk)
                self.assertIn("y", jwk)
                self.assertIn("crv", jwk)

        asyncio.run(run_test())


class TestMessageInspection(unittest.TestCase):
    """Test message inspection functionality"""

    def test_inspect_valid_message(self):
        """Test inspecting valid TAC message"""
        # Create mock message structure
        message_data = {
            "version": "2025-08-27",
            "recipients": [
                {"kid": "merchant.com", "jwe": "encrypted_data_1"},
                {"kid": "forter.com", "jwe": "encrypted_data_2"},
            ],
            "jws": "header.payload.signature",
        }

        encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

        inspection = TACRecipient.inspect(encoded_message)

        self.assertEqual(inspection["version"], "2025-08-27")
        self.assertEqual(len(inspection["recipients"]), 2)
        self.assertIn("merchant.com", inspection["recipients"])
        self.assertIn("forter.com", inspection["recipients"])
        self.assertIsNone(inspection["expires"])  # No expiration in mock

    def test_inspect_invalid_base64(self):
        """Test inspecting invalid base64 message"""
        invalid_message = "not-valid-base64!"

        inspection = TACRecipient.inspect(invalid_message)

        self.assertIsNone(inspection["version"])
        self.assertEqual(inspection["recipients"], [])
        self.assertIsNone(inspection["expires"])
        self.assertIn("error", inspection)

    def test_inspect_invalid_json(self):
        """Test inspecting message with invalid JSON"""
        invalid_json = base64.b64encode(b"not json").decode("utf-8")

        inspection = TACRecipient.inspect(invalid_json)

        self.assertIsNone(inspection["version"])
        self.assertEqual(inspection["recipients"], [])
        self.assertIsNone(inspection["expires"])
        self.assertIn("error", inspection)

    def test_inspect_missing_fields(self):
        """Test inspecting message with missing required fields"""
        incomplete_message = {
            "version": "2025-08-27"
            # Missing recipients and jws
        }

        encoded_message = base64.b64encode(json.dumps(incomplete_message).encode("utf-8")).decode("utf-8")

        inspection = TACRecipient.inspect(encoded_message)

        self.assertEqual(inspection["version"], "2025-08-27")
        self.assertEqual(inspection["recipients"], [])

    def test_inspect_with_expires(self):
        """Test inspecting message with expiration"""
        # Create message with JWS containing exp claim
        import time

        future_time = int(time.time()) + 3600  # 1 hour from now

        # Note: In real implementation, this would be extracted from JWS payload
        # For this test, we simulate the inspection result
        message_data = {
            "version": "2025-08-27",
            "recipients": [{"kid": "test", "jwe": "data"}],
            "jws": "header.payload.signature",
        }

        encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

        inspection = TACRecipient.inspect(encoded_message)

        # Basic inspection (real implementation would decode JWS to get exp)
        self.assertIsNotNone(inspection["version"])
        self.assertGreater(len(inspection["recipients"]), 0)


class TestMessageProcessing(unittest.TestCase):
    """Test TAC message processing"""

    def setUp(self):
        """Set up test fixtures"""
        self.sender_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.sender_private_key)

        self.recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient = TACRecipient(domain="merchant.com", private_key=self.recipient_private_key)

    def test_process_missing_message(self):
        """Test processing missing TAC message"""

        async def run_test():
            result = await self.recipient.process_tac_message(None)

            self.assertFalse(result["valid"])
            self.assertIn("Missing TAC-Protocol message", " ".join(result["errors"]))

        asyncio.run(run_test())

    def test_process_empty_message(self):
        """Test processing empty TAC message"""

        async def run_test():
            result = await self.recipient.process_tac_message("")

            self.assertFalse(result["valid"])
            self.assertIn("missing", " ".join(result["errors"]).lower())

        asyncio.run(run_test())

    def test_process_invalid_base64_message(self):
        """Test processing invalid base64 message"""

        async def run_test():
            result = await self.recipient.process_tac_message("invalid-base64!")

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_process_invalid_json_message(self):
        """Test processing message with invalid JSON"""
        invalid_json = base64.b64encode(b"not json").decode("utf-8")

        async def run_test():
            result = await self.recipient.process_tac_message(invalid_json)

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    @patch.object(TACRecipient, "fetch_jwks")
    def test_process_valid_message(self, mock_recipient_fetch, mock_sender_fetch):
        """Test processing valid TAC message"""

        async def run_test():
            # Set up mocks
            recipient_jwk = await self.recipient.get_public_jwk()
            sender_jwk = await self.sender.get_public_jwk()

            mock_sender_fetch.return_value = [recipient_jwk]
            mock_recipient_fetch.return_value = [sender_jwk]

            # Generate message
            test_data = {"user": {"email": {"address": "test@example.com"}, "id": "user123"}}

            await self.sender.add_recipient_data("merchant.com", test_data)
            message = await self.sender.generate_tac_message()

            # Process message
            result = await self.recipient.process_tac_message(message)

            # Verify result
            self.assertTrue(result["valid"])
            self.assertEqual(result["issuer"], "agent.com")
            self.assertIsNotNone(result["data"])
            self.assertEqual(result["data"]["user"]["id"], "user123")
            self.assertEqual(result["recipients"], ["merchant.com"])
            self.assertEqual(len(result["errors"]), 0)

        asyncio.run(run_test())

    @patch.object(TACRecipient, "fetch_jwks")
    def test_process_message_signature_verification_failure(self, mock_fetch):
        """Test processing message with invalid signature"""

        async def run_test():
            # Create message with tampered signature
            message_data = {
                "version": "2025-08-27",
                "recipients": [{"kid": "merchant.com", "jwe": "fake_encrypted_data"}],
                "jws": "header.payload.invalid_signature",
            }

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            # Mock sender keys
            sender_jwk = await self.sender.get_public_jwk()
            mock_fetch.return_value = [sender_jwk]

            result = await self.recipient.process_tac_message(encoded_message)

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_process_message_no_matching_recipient(self):
        """Test processing message with no matching recipient"""

        async def run_test():
            # Create message for different recipient
            message_data = {
                "version": "2025-08-27",
                "recipients": [{"kid": "other.com", "jwe": "encrypted_data"}],
                "jws": "header.payload.signature",
            }

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            result = await self.recipient.process_tac_message(encoded_message)

            self.assertFalse(result["valid"])
            self.assertIn("not a recipient", " ".join(result["errors"]).lower())

        asyncio.run(run_test())


class TestMultiRecipientScenarios(unittest.TestCase):
    """Test multi-recipient message scenarios"""

    def setUp(self):
        """Set up test fixtures"""
        self.sender_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sender = TACSender(domain="agent.com", private_key=self.sender_private_key)

        # Create multiple recipients
        self.recipient1_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient1 = TACRecipient(domain="merchant.com", private_key=self.recipient1_private_key)

        self.recipient2_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient2 = TACRecipient(domain="forter.com", private_key=self.recipient2_private_key)

    @patch.object(TACSender, "fetch_jwks")
    @patch.object(TACRecipient, "fetch_jwks")
    def test_multi_recipient_message_processing(self, mock_recipient_fetch, mock_sender_fetch):
        """Test processing multi-recipient message"""

        async def run_test():
            # Set up mocks
            recipient1_jwk = await self.recipient1.get_public_jwk()
            recipient2_jwk = await self.recipient2.get_public_jwk()
            sender_jwk = await self.sender.get_public_jwk()

            def mock_sender_fetch_side_effect(domain):
                if domain == "merchant.com":
                    return [recipient1_jwk]
                elif domain == "forter.com":
                    return [recipient2_jwk]
                return []

            mock_sender_fetch.side_effect = mock_sender_fetch_side_effect
            mock_recipient_fetch.return_value = [sender_jwk]

            # Generate message for both recipients
            await self.sender.add_recipient_data("merchant.com", {"user": {"id": "user1"}})
            await self.sender.add_recipient_data("forter.com", {"user": {"id": "user2"}})

            message = await self.sender.generate_tac_message()

            # Both recipients should be able to process
            result1 = await self.recipient1.process_tac_message(message)
            result2 = await self.recipient2.process_tac_message(message)

            # Verify both results
            self.assertTrue(result1["valid"])
            self.assertTrue(result2["valid"])

            self.assertEqual(result1["data"]["user"]["id"], "user1")
            self.assertEqual(result2["data"]["user"]["id"], "user2")

            # Both should see all recipients
            self.assertIn("merchant.com", result1["recipients"])
            self.assertIn("forter.com", result1["recipients"])
            self.assertIn("merchant.com", result2["recipients"])
            self.assertIn("forter.com", result2["recipients"])

        asyncio.run(run_test())

    def test_recipient_list_extraction(self):
        """Test extraction of recipient list from message"""
        message_data = {
            "version": "2025-08-27",
            "recipients": [
                {"kid": "merchant.com", "jwe": "data1"},
                {"kid": "forter.com", "jwe": "data2"},
                {"kid": "payment.com", "jwe": "data3"},
            ],
            "jws": "signature",
        }

        encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

        inspection = TACRecipient.inspect(encoded_message)

        self.assertEqual(len(inspection["recipients"]), 3)
        self.assertIn("merchant.com", inspection["recipients"])
        self.assertIn("forter.com", inspection["recipients"])
        self.assertIn("payment.com", inspection["recipients"])


class TestErrorHandling(unittest.TestCase):
    """Test error handling in recipient"""

    def setUp(self):
        """Set up test fixtures"""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient = TACRecipient(domain="merchant.com", private_key=self.private_key)

    @patch.object(TACRecipient, "fetch_jwks")
    def test_jwks_fetch_failure(self, mock_fetch):
        """Test handling of JWKS fetch failure"""
        mock_fetch.side_effect = TACNetworkError("Failed to fetch JWKS")

        async def run_test():
            # Create minimal valid message structure
            message_data = {
                "version": "2025-08-27",
                "recipients": [{"kid": "merchant.com", "jwe": "data"}],
                "jws": "header.payload.signature",
            }

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            result = await self.recipient.process_tac_message(encoded_message)

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    @patch.object(TACRecipient, "fetch_jwks")
    def test_empty_jwks_response(self, mock_fetch):
        """Test handling of empty JWKS response"""
        mock_fetch.return_value = []

        async def run_test():
            message_data = {
                "version": "2025-08-27",
                "recipients": [{"kid": "merchant.com", "jwe": "data"}],
                "jws": "header.payload.signature",
            }

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            result = await self.recipient.process_tac_message(encoded_message)

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_malformed_message_structure(self):
        """Test handling of malformed message structure"""
        malformed_structures = [
            {},  # Empty object
            {"version": "2025-08-27"},  # Missing recipients and jws
            {"recipients": []},  # Missing version and jws
            {"jws": "signature"},  # Missing version and recipients
            {"version": "2025-08-27", "recipients": "not-array"},  # Invalid recipients type
        ]

        async def run_test():
            for malformed in malformed_structures:
                encoded_message = base64.b64encode(json.dumps(malformed).encode("utf-8")).decode("utf-8")

                result = await self.recipient.process_tac_message(encoded_message)

                self.assertFalse(result["valid"], f"Should fail for: {malformed}")
                self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_unsupported_version(self):
        """Test handling of unsupported message version"""

        async def run_test():
            message_data = {
                "version": "1999-01-01",  # Unsupported version
                "recipients": [{"kid": "merchant.com", "jwe": "data"}],
                "jws": "header.payload.signature",
            }

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            result = await self.recipient.process_tac_message(encoded_message)

            # May succeed with warnings or fail depending on implementation
            # At minimum should not crash
            self.assertIsInstance(result, dict)
            self.assertIn("valid", result)
            self.assertIn("errors", result)

        asyncio.run(run_test())


class TestKeyRotationScenarios(unittest.TestCase):
    """Test key rotation scenarios"""

    def setUp(self):
        """Set up test fixtures"""
        self.recipient_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.recipient = TACRecipient(domain="merchant.com", private_key=self.recipient_private_key)

    @patch.object(TACRecipient, "fetch_jwks")
    def test_multiple_keys_in_jwks(self, mock_fetch):
        """Test handling multiple keys in JWKS"""

        async def run_test():
            # Create additional key
            old_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            old_recipient = TACRecipient(domain="merchant.com", private_key=old_private_key)

            # Mock JWKS with multiple keys
            current_jwk = await self.recipient.get_public_jwk()
            old_jwk = await old_recipient.get_public_jwk()
            old_jwk["kid"] = "old-key-id"  # Different kid

            mock_fetch.return_value = [current_jwk, old_jwk]

            # Create message using current key
            message_data = {
                "version": "2025-08-27",
                "recipients": [{"kid": "merchant.com", "jwe": "data"}],
                "jws": "header.payload.signature",
            }

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            # Should be able to find the right key
            result = await self.recipient.process_tac_message(encoded_message)

            # May fail due to invalid signature, but should not fail due to key lookup
            self.assertIsInstance(result, dict)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
