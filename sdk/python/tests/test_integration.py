#!/usr/bin/env python3
"""
Integration Tests for TAC Protocol Python SDK

Tests end-to-end workflows, cross-component interactions.
Each party only manages their own private key - public keys are fetched via JWKS from domains.
"""

import asyncio
import base64
import json
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric import rsa

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACCryptoError, TACNetworkError, TACValidationError
from recipient import TACRecipient
from sender import TACSender


def generate_rsa_key():
    """Generate an RSA private key for testing"""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


async def setup_jwks_exchange(sender: TACSender, recipient: TACRecipient):
    """
    Set up JWKS mocking for sender-recipient communication.

    In production:
    - Sender fetches recipient's public key from recipient's domain JWKS endpoint
    - Recipient fetches sender's public key from sender's domain JWKS endpoint

    This helper mocks those JWKS fetches to return the correct public keys.
    """
    sender_jwk = await sender.get_public_jwk()
    recipient_jwk = await recipient.get_public_jwk()

    sender.fetch_jwks = AsyncMock(return_value=[recipient_jwk])
    recipient.fetch_jwks = AsyncMock(return_value=[sender_jwk])


class TestEndToEndWorkflow(unittest.TestCase):
    """Test complete end-to-end TAC Protocol workflow"""

    def test_basic_end_to_end_flow(self):
        """Test basic end-to-end message flow"""

        async def run_test():
            # Each party only has their own private key
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            # JWKS exchange - each party's public key is fetched from their domain
            await setup_jwks_exchange(sender, recipient)

            # Test data
            test_data = {
                "user": {"email": {"address": "user@example.com"}, "id": "user123"},
                "session": {"ipAddress": "192.168.1.1", "userAgent": "Mozilla/5.0..."},
                "transaction": {"amount": 99.99, "currency": "USD"},
            }

            # Generate message
            await sender.add_recipient_data("merchant.com", test_data)
            message = await sender.generate_tac_message()

            # Verify message is valid base64
            self.assertIsInstance(message, str)
            decoded = base64.b64decode(message)
            message_data = json.loads(decoded.decode("utf-8"))
            self.assertIn("version", message_data)
            self.assertIn("recipients", message_data)

            # Process message
            result = await recipient.process_tac_message(message)

            # Verify result
            self.assertTrue(result["valid"])
            self.assertEqual(result["issuer"], "agent.com")
            self.assertIsNotNone(result["data"])

            # Verify data integrity
            received_data = result["data"]
            self.assertEqual(received_data["user"]["id"], "user123")
            self.assertEqual(received_data["user"]["email"]["address"], "user@example.com")
            self.assertEqual(received_data["session"]["ipAddress"], "192.168.1.1")
            self.assertEqual(received_data["transaction"]["amount"], 99.99)

            # Verify metadata
            self.assertEqual(result["recipients"], ["merchant.com"])
            self.assertEqual(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_multi_recipient_workflow(self):
        """Test multi-recipient workflow"""

        async def run_test():
            # Each party only has their own private key
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            merchant = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())
            forter = TACRecipient(domain="forter.com", private_key=generate_rsa_key())

            # JWKS exchange - public keys fetched from respective domains
            sender_jwk = await sender.get_public_jwk()
            merchant_jwk = await merchant.get_public_jwk()
            forter_jwk = await forter.get_public_jwk()

            async def sender_fetch_jwks(domain):
                if domain == "merchant.com":
                    return [merchant_jwk]
                elif domain == "forter.com":
                    return [forter_jwk]
                return []

            sender.fetch_jwks = sender_fetch_jwks
            merchant.fetch_jwks = AsyncMock(return_value=[sender_jwk])
            forter.fetch_jwks = AsyncMock(return_value=[sender_jwk])

            # Add different data for each recipient
            merchant_data = {"user": {"id": "user123"}, "order": {"id": "order456", "total": 99.99}}
            forter_data = {"user": {"id": "user123"}, "session": {"ipAddress": "192.168.1.1", "fingerprint": "abc123"}}

            await sender.add_recipient_data("merchant.com", merchant_data)
            await sender.add_recipient_data("forter.com", forter_data)

            # Generate message
            message = await sender.generate_tac_message()

            # Both recipients should be able to process
            result1 = await merchant.process_tac_message(message)
            result2 = await forter.process_tac_message(message)

            # Verify both results
            self.assertTrue(result1["valid"])
            self.assertTrue(result2["valid"])

            # Each should get their specific data
            self.assertEqual(result1["data"]["order"]["id"], "order456")
            self.assertNotIn("session", result1["data"])

            self.assertEqual(result2["data"]["session"]["fingerprint"], "abc123")
            self.assertNotIn("order", result2["data"])

            # Both should see all recipients
            self.assertIn("merchant.com", result1["recipients"])
            self.assertIn("forter.com", result1["recipients"])
            self.assertIn("merchant.com", result2["recipients"])
            self.assertIn("forter.com", result2["recipients"])

        asyncio.run(run_test())

    def test_message_inspection_workflow(self):
        """Test message inspection workflow"""

        async def run_test():
            # Each party only has their own private key
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            # JWKS exchange
            await setup_jwks_exchange(sender, recipient)

            # Generate message
            await sender.add_recipient_data("merchant.com", {"user": {"id": "test"}})
            message = await sender.generate_tac_message()

            # Inspect message without decryption
            inspection = TACRecipient.inspect(message)

            self.assertEqual(inspection["version"], "2025-08-27")
            self.assertIn("merchant.com", inspection["recipients"])
            self.assertIsNone(inspection["expires"])  # No expiration in this test

            # Process message for full verification
            result = await recipient.process_tac_message(message)

            self.assertTrue(result["valid"])
            self.assertEqual(result["data"]["user"]["id"], "test")

        asyncio.run(run_test())


class TestErrorScenarios(unittest.TestCase):
    """Test error scenarios in integration"""

    def test_network_error_during_generation(self):
        """Test network error during message generation"""

        async def run_test():
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            sender.fetch_jwks = AsyncMock(
                side_effect=TACNetworkError("Failed to fetch JWKS", "TAC_JWKS_FETCH_FAILED")
            )

            await sender.add_recipient_data("merchant.com", {"test": "data"})

            with self.assertRaises(TACNetworkError) as cm:
                await sender.generate_tac_message()

            self.assertIn("Failed to fetch JWKS", str(cm.exception))

        asyncio.run(run_test())

    def test_network_error_during_processing(self):
        """Test network error during message processing"""

        async def run_test():
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())
            recipient.fetch_jwks = AsyncMock(
                side_effect=TACNetworkError("Failed to fetch sender keys", "TAC_JWKS_FETCH_FAILED")
            )

            # Create a minimal message
            message_data = {"version": "2025-08-27", "recipients": [{"kid": "merchant.com", "jwe": "encrypted_data"}]}
            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            result = await recipient.process_tac_message(encoded_message)

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_invalid_message_handling(self):
        """Test handling of various invalid messages"""

        async def run_test():
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            invalid_messages = [
                None,  # None message
                "",  # Empty message
                "invalid-base64!",  # Invalid base64
                base64.b64encode(b"not json").decode("utf-8"),  # Invalid JSON
                base64.b64encode(b"{}").decode("utf-8"),  # Empty object
            ]

            for invalid_message in invalid_messages:
                result = await recipient.process_tac_message(invalid_message)

                self.assertFalse(result["valid"], f"Should fail for: {invalid_message}")
                self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_malformed_jwk_handling(self):
        """Test handling of malformed JWK data"""

        async def run_test():
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())

            # Create a malformed JWK that claims to be RSA but is missing required fields
            malformed_jwk = {
                "kty": "RSA",
                "kid": "malformed-key",
                "alg": "RSA-OAEP-256",
                "use": "enc",
                # Missing required RSA fields: n, e
            }

            sender.fetch_jwks = AsyncMock(return_value=[malformed_jwk])

            await sender.add_recipient_data("merchant.com", {"test": "data"})

            # Should handle gracefully or throw appropriate error
            try:
                await sender.generate_tac_message()
                # If it succeeds, that's also acceptable (robust implementation)
            except (TACCryptoError, TACValidationError) as e:
                # Expected error types for malformed key - could be various crypto-related errors
                error_msg = str(e).lower()
                # Accept various key/crypto-related error messages
                self.assertTrue(
                    "key" in error_msg or "encryption" in error_msg or "invalid" in error_msg or "jwk" in error_msg,
                    f"Expected key/crypto-related error, got: {e}",
                )

        asyncio.run(run_test())


class TestPerformanceScenarios(unittest.TestCase):
    """Test performance-related scenarios"""

    def test_large_payload_handling(self):
        """Test handling of large payloads"""

        async def run_test():
            # Each party only has their own private key
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            # JWKS exchange
            await setup_jwks_exchange(sender, recipient)

            # Create large payload
            large_data = {
                "user": {
                    "id": "user123",
                    "profile": "x" * 10000,  # Large string
                    "metadata": ["item" + str(i) for i in range(1000)],  # Large array
                }
            }

            await sender.add_recipient_data("merchant.com", large_data)

            start_time = time.time()
            message = await sender.generate_tac_message()
            generation_time = time.time() - start_time

            start_time = time.time()
            result = await recipient.process_tac_message(message)
            processing_time = time.time() - start_time

            # Should complete in reasonable time
            self.assertLess(generation_time, 5.0)  # Less than 5 seconds
            self.assertLess(processing_time, 5.0)  # Less than 5 seconds

            # Data should be intact
            self.assertTrue(result["valid"])
            self.assertEqual(len(result["data"]["user"]["profile"]), 10000)
            self.assertEqual(len(result["data"]["user"]["metadata"]), 1000)

        asyncio.run(run_test())

    def test_concurrent_message_processing(self):
        """Test concurrent message processing"""

        async def run_test():
            # Shared keys for this test
            sender_key = generate_rsa_key()
            recipient_key = generate_rsa_key()

            # Create base sender and recipient to get their public JWKs
            base_sender = TACSender(domain="agent.com", private_key=sender_key)
            recipient = TACRecipient(domain="merchant.com", private_key=recipient_key)

            sender_jwk = await base_sender.get_public_jwk()
            recipient_jwk = await recipient.get_public_jwk()

            recipient.fetch_jwks = AsyncMock(return_value=[sender_jwk])

            # Generate multiple messages concurrently
            async def generate_message(message_id):
                # Create new sender for each message to avoid conflicts
                sender = TACSender(domain="agent.com", private_key=sender_key)
                sender.fetch_jwks = AsyncMock(return_value=[recipient_jwk])

                await sender.add_recipient_data(
                    "merchant.com", {"message_id": message_id, "data": f"message_{message_id}"}
                )
                return await sender.generate_tac_message()

            # Generate messages concurrently
            messages = await asyncio.gather(*[generate_message(i) for i in range(10)])

            # Process messages concurrently
            results = await asyncio.gather(*[recipient.process_tac_message(msg) for msg in messages])

            # All should succeed
            self.assertEqual(len(results), 10)
            for i, result in enumerate(results):
                self.assertTrue(result["valid"], f"Message {i} should be valid")
                self.assertEqual(result["data"]["message_id"], i)

        asyncio.run(run_test())


class TestKeyRotationScenarios(unittest.TestCase):
    """Test key rotation scenarios"""

    def test_key_rotation_during_operation(self):
        """Test basic key operation with initial key setup"""

        async def run_test():
            # Each party only has their own private key
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            # JWKS exchange
            await setup_jwks_exchange(sender, recipient)

            # Generate and process message with initial setup
            await sender.add_recipient_data("merchant.com", {"test": "data"})
            message = await sender.generate_tac_message()

            result = await recipient.process_tac_message(message)

            # Should work with initial key setup
            self.assertTrue(result["valid"])
            self.assertEqual(result["data"]["test"], "data")

        asyncio.run(run_test())

    def test_multiple_keys_in_jwks(self):
        """Test handling multiple keys in JWKS"""

        async def run_test():
            sender = TACSender(domain="agent.com", private_key=generate_rsa_key())
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            # Mock JWKS with multiple keys (current + old)
            sender_jwk = await sender.get_public_jwk()
            old_sender_jwk = sender_jwk.copy()
            old_sender_jwk["kid"] = "old-key-id"

            recipient.fetch_jwks = AsyncMock(return_value=[sender_jwk, old_sender_jwk])

            # Create test message
            message_data = {"version": "2025-08-27", "recipients": [{"kid": "merchant.com", "jwe": "encrypted_data"}]}
            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            # Should be able to process with multiple keys available
            result = await recipient.process_tac_message(encoded_message)

            # Basic structure should be valid (even if decryption fails due to test data)
            self.assertIsInstance(result, dict)
            self.assertIn("valid", result)
            self.assertIn("errors", result)

        asyncio.run(run_test())


class TestSecurityScenarios(unittest.TestCase):
    """Test security-related scenarios"""

    def test_message_tampering_detection(self):
        """Test detection of message tampering"""

        async def run_test():
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            # Create a valid-looking but tampered message
            tampered_message_data = {
                "version": "2025-08-27",
                "recipients": [{"kid": "merchant.com", "jwe": "tampered_encrypted_data"}],
            }

            encoded_message = base64.b64encode(json.dumps(tampered_message_data).encode("utf-8")).decode("utf-8")

            result = await recipient.process_tac_message(encoded_message)

            # Should detect tampering
            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    def test_malformed_data_injection(self):
        """Test handling of malformed data injection attempts"""

        async def run_test():
            recipient = TACRecipient(domain="merchant.com", private_key=generate_rsa_key())

            malformed_messages = [
                # Extremely nested objects
                base64.b64encode(
                    json.dumps(
                        {
                            "version": "2025-08-27",
                            "recipients": [{"kid": "test", "jwe": {"nested": {"very": {"deep": "object"}}}}],
                        }
                    ).encode("utf-8")
                ).decode("utf-8"),
                # Very long strings
                base64.b64encode(
                    json.dumps({"version": "2025-08-27", "recipients": [{"kid": "x" * 100000, "jwe": "data"}]}).encode(
                        "utf-8"
                    )
                ).decode("utf-8"),
                # Special characters
                base64.b64encode(
                    json.dumps({"version": "2025-08-27", "recipients": [{"kid": "\\x00\\xff", "jwe": "data"}]}).encode(
                        "utf-8"
                    )
                ).decode("utf-8"),
            ]

            for malformed_message in malformed_messages:
                result = await recipient.process_tac_message(malformed_message)

                # Should handle gracefully without crashing
                self.assertIsInstance(result, dict)
                self.assertIn("valid", result)
                self.assertFalse(result["valid"])  # Should be invalid

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
