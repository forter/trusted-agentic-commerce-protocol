#!/usr/bin/env python3
"""
Error Handling Tests for TAC Protocol Python SDK

Tests error types, codes, and proper error propagation.
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from errors import TACCryptoError, TACError, TACErrorCodes, TACMessageError, TACNetworkError, TACValidationError
from recipient import TACRecipient
from sender import TACSender


class TestErrorTypes(unittest.TestCase):
    """Test different error types"""

    def test_tac_error_base_class(self):
        """Test TACError base class"""
        error = TACError("Test error", TACErrorCodes.DOMAIN_REQUIRED)

        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "Test error")
        self.assertEqual(error.code, TACErrorCodes.DOMAIN_REQUIRED)
        self.assertEqual(error.message, "Test error")

    def test_tac_validation_error(self):
        """Test TACValidationError"""
        error = TACValidationError("Invalid domain", TACErrorCodes.INVALID_DOMAIN)

        self.assertIsInstance(error, TACError)
        self.assertEqual(str(error), "Invalid domain")
        self.assertEqual(error.code, TACErrorCodes.INVALID_DOMAIN)

    def test_tac_crypto_error(self):
        """Test TACCryptoError"""
        error = TACCryptoError("Encryption failed", TACErrorCodes.ENCRYPTION_FAILED)

        self.assertIsInstance(error, TACError)
        self.assertEqual(str(error), "Encryption failed")
        self.assertEqual(error.code, TACErrorCodes.ENCRYPTION_FAILED)

    def test_tac_network_error(self):
        """Test TACNetworkError"""
        error = TACNetworkError("Network timeout", TACErrorCodes.NETWORK_TIMEOUT)

        self.assertIsInstance(error, TACError)
        self.assertEqual(str(error), "Network timeout")
        self.assertEqual(error.code, TACErrorCodes.NETWORK_TIMEOUT)

    def test_tac_message_error(self):
        """Test TACMessageError"""
        error = TACMessageError("Invalid message", TACErrorCodes.INVALID_MESSAGE_FORMAT)

        self.assertIsInstance(error, TACError)
        self.assertEqual(str(error), "Invalid message")
        self.assertEqual(error.code, TACErrorCodes.INVALID_MESSAGE_FORMAT)


class TestErrorCodes(unittest.TestCase):
    """Test error codes enum"""

    def test_validation_error_codes(self):
        """Test validation error codes"""
        self.assertEqual(TACErrorCodes.DOMAIN_REQUIRED, "TAC_DOMAIN_REQUIRED")
        self.assertEqual(TACErrorCodes.INVALID_DOMAIN, "TAC_INVALID_DOMAIN")
        self.assertEqual(TACErrorCodes.PRIVATE_KEY_REQUIRED, "TAC_PRIVATE_KEY_REQUIRED")
        self.assertEqual(TACErrorCodes.INVALID_KEY_DATA, "TAC_INVALID_KEY_DATA")
        self.assertEqual(TACErrorCodes.INVALID_DATA, "TAC_INVALID_DATA")
        self.assertEqual(TACErrorCodes.UNSUPPORTED_KEY_TYPE, "TAC_UNSUPPORTED_KEY_TYPE")

    def test_network_error_codes(self):
        """Test network error codes"""
        self.assertEqual(TACErrorCodes.HTTP_ERROR, "TAC_HTTP_ERROR")
        self.assertEqual(TACErrorCodes.NETWORK_TIMEOUT, "TAC_NETWORK_TIMEOUT")
        self.assertEqual(TACErrorCodes.JWKS_FETCH_FAILED, "TAC_JWKS_FETCH_FAILED")

    def test_crypto_error_codes(self):
        """Test crypto error codes"""
        self.assertEqual(TACErrorCodes.ENCRYPTION_FAILED, "TAC_ENCRYPTION_FAILED")
        self.assertEqual(TACErrorCodes.DECRYPTION_FAILED, "TAC_DECRYPTION_FAILED")
        self.assertEqual(TACErrorCodes.JWT_SIGNING_FAILED, "TAC_JWT_SIGNING_FAILED")
        self.assertEqual(TACErrorCodes.JWT_VERIFICATION_FAILED, "TAC_JWT_VERIFICATION_FAILED")

    def test_message_error_codes(self):
        """Test message error codes"""
        self.assertEqual(TACErrorCodes.INVALID_MESSAGE_FORMAT, "TAC_INVALID_MESSAGE_FORMAT")
        self.assertEqual(TACErrorCodes.MESSAGE_EXPIRED, "TAC_MESSAGE_EXPIRED")
        self.assertEqual(TACErrorCodes.INVALID_SIGNATURE, "TAC_INVALID_SIGNATURE")


class TestSenderErrorHandling(unittest.TestCase):
    """Test error handling in TACSender"""

    def test_invalid_domain_error(self):
        """Test invalid domain raises proper error"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Empty domain
        with self.assertRaises(TACValidationError) as cm:
            TACSender(domain="", private_key=private_key)
        self.assertEqual(cm.exception.code, TACErrorCodes.DOMAIN_REQUIRED)

        # None domain
        with self.assertRaises(TACValidationError) as cm:
            TACSender(domain=None, private_key=private_key)
        self.assertEqual(cm.exception.code, TACErrorCodes.DOMAIN_REQUIRED)

    def test_invalid_private_key_error(self):
        """Test invalid private key raises proper error"""
        # None private key
        with self.assertRaises(TACValidationError) as cm:
            TACSender(domain="test.com", private_key=None)
        self.assertEqual(cm.exception.code, TACErrorCodes.PRIVATE_KEY_REQUIRED)

        # Invalid private key type
        with self.assertRaises(TACCryptoError) as cm:
            TACSender(domain="test.com", private_key="not-a-key")
        self.assertEqual(cm.exception.code, TACErrorCodes.INVALID_KEY_DATA)

    def test_invalid_recipient_data_error(self):
        """Test invalid recipient data raises proper error"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sender = TACSender(domain="test.com", private_key=private_key)

        async def run_test():
            # Invalid domain
            with self.assertRaises(TACValidationError) as cm:
                await sender.add_recipient_data("", {"test": "data"})
            self.assertEqual(cm.exception.code, TACErrorCodes.INVALID_DOMAIN)

            # None data
            with self.assertRaises(TACValidationError) as cm:
                await sender.add_recipient_data("test.com", None)
            self.assertEqual(cm.exception.code, TACErrorCodes.INVALID_DATA)

        asyncio.run(run_test())

    def test_no_recipient_data_error(self):
        """Test no recipient data raises proper error"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sender = TACSender(domain="test.com", private_key=private_key)

        async def run_test():
            with self.assertRaises(TACValidationError) as cm:
                await sender.generate_tac_message()
            self.assertEqual(cm.exception.code, TACErrorCodes.NO_RECIPIENT_DATA)

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    def test_jwks_fetch_error(self, mock_fetch):
        """Test JWKS fetch error propagation"""
        mock_fetch.side_effect = TACNetworkError("Network error", TACErrorCodes.JWKS_FETCH_FAILED)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sender = TACSender(domain="test.com", private_key=private_key)

        async def run_test():
            await sender.add_recipient_data("merchant.com", {"test": "data"})

            with self.assertRaises(TACNetworkError) as cm:
                await sender.generate_tac_message()
            self.assertEqual(cm.exception.code, TACErrorCodes.JWKS_FETCH_FAILED)

        asyncio.run(run_test())

    @patch.object(TACSender, "fetch_jwks")
    def test_encryption_error(self, mock_fetch):
        """Test encryption error handling"""
        # Mock invalid JWK that should cause encryption to fail
        invalid_jwk = {"kty": "RSA", "kid": "test-key", "n": "invalid-modulus", "e": "AQAB"}
        mock_fetch.return_value = [invalid_jwk]

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sender = TACSender(domain="test.com", private_key=private_key)

        async def run_test():
            await sender.add_recipient_data("merchant.com", {"test": "data"})

            with self.assertRaises(TACCryptoError) as cm:
                await sender.generate_tac_message()
            self.assertEqual(cm.exception.code, TACErrorCodes.ENCRYPTION_FAILED)

        asyncio.run(run_test())


class TestRecipientErrorHandling(unittest.TestCase):
    """Test error handling in TACRecipient"""

    def test_invalid_domain_error(self):
        """Test invalid domain raises proper error"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Empty domain
        with self.assertRaises(TACValidationError) as cm:
            TACRecipient(domain="", private_key=private_key)
        self.assertEqual(cm.exception.code, TACErrorCodes.DOMAIN_REQUIRED)

        # None domain
        with self.assertRaises(TACValidationError) as cm:
            TACRecipient(domain=None, private_key=private_key)
        self.assertEqual(cm.exception.code, TACErrorCodes.DOMAIN_REQUIRED)

    def test_invalid_private_key_error(self):
        """Test invalid private key raises proper error"""
        # None private key
        with self.assertRaises(TACValidationError) as cm:
            TACRecipient(domain="test.com", private_key=None)
        self.assertEqual(cm.exception.code, TACErrorCodes.PRIVATE_KEY_REQUIRED)

        # Invalid private key type
        with self.assertRaises(TACCryptoError) as cm:
            TACRecipient(domain="test.com", private_key="not-a-key")
        self.assertEqual(cm.exception.code, TACErrorCodes.INVALID_KEY_DATA)

    def test_missing_message_error(self):
        """Test missing message handling"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient = TACRecipient(domain="test.com", private_key=private_key)

        async def run_test():
            result = await recipient.process_tac_message(None)

            self.assertFalse(result["valid"])
            self.assertIn("errors", result)
            self.assertGreater(len(result["errors"]), 0)
            self.assertIn("Missing", result["errors"][0])

        asyncio.run(run_test())

    def test_invalid_message_format_error(self):
        """Test invalid message format handling"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient = TACRecipient(domain="test.com", private_key=private_key)

        async def run_test():
            # Invalid base64
            result = await recipient.process_tac_message("invalid-base64!")
            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

            # Invalid JSON
            import base64

            invalid_json = base64.b64encode(b"not json").decode("utf-8")
            result = await recipient.process_tac_message(invalid_json)
            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())

    @patch.object(TACRecipient, "fetch_jwks")
    def test_jwks_fetch_error_in_recipient(self, mock_fetch):
        """Test JWKS fetch error in recipient"""
        mock_fetch.side_effect = TACNetworkError("Network error", TACErrorCodes.NETWORK_TIMEOUT)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        recipient = TACRecipient(domain="test.com", private_key=private_key)

        async def run_test():
            # Create minimal valid message structure
            import base64
            import json

            message_data = {"version": "2025-08-27", "recipients": [{"kid": "test.com", "jwe": "encrypted_data"}]}

            encoded_message = base64.b64encode(json.dumps(message_data).encode("utf-8")).decode("utf-8")

            result = await recipient.process_tac_message(encoded_message)

            self.assertFalse(result["valid"])
            self.assertGreater(len(result["errors"]), 0)

        asyncio.run(run_test())


class TestErrorMessageDetails(unittest.TestCase):
    """Test error message details and context"""

    def test_error_context_preservation(self):
        """Test that error context is preserved"""
        original_error = ValueError("Original error message")

        tac_error = TACCryptoError(f"Encryption failed: {str(original_error)}", TACErrorCodes.ENCRYPTION_FAILED)

        self.assertIn("Original error message", str(tac_error))
        self.assertEqual(tac_error.code, TACErrorCodes.ENCRYPTION_FAILED)

    def test_error_chaining(self):
        """Test error chaining works properly"""
        try:
            try:
                raise ValueError("Low level error")
            except ValueError as e:
                raise TACCryptoError(f"High level error: {str(e)}", TACErrorCodes.ENCRYPTION_FAILED) from e
        except TACCryptoError as tac_error:
            self.assertIn("High level error", str(tac_error))
            self.assertIn("Low level error", str(tac_error))
            self.assertIsInstance(tac_error.__cause__, ValueError)

    def test_error_without_code(self):
        """Test error creation without explicit code"""
        error = TACError("Test error")

        self.assertEqual(str(error), "Test error")
        self.assertEqual(error.code, "TAC_UNKNOWN_ERROR")  # Default code


class TestEdgeCaseErrorHandling(unittest.TestCase):
    """Test edge case error scenarios"""

    def test_extremely_long_error_messages(self):
        """Test handling of extremely long error messages"""
        long_message = "x" * 10000  # Very long error message

        error = TACValidationError(long_message, TACErrorCodes.INVALID_DOMAIN)

        self.assertEqual(str(error), long_message)
        self.assertEqual(len(str(error)), 10000)

    def test_unicode_error_messages(self):
        """Test handling of unicode error messages"""
        unicode_message = "Error with émojis: 🚫🔑 and ñoñ-ASCII çharacters"

        error = TACCryptoError(unicode_message, TACErrorCodes.ENCRYPTION_FAILED)

        self.assertEqual(str(error), unicode_message)
        self.assertIn("émojis", str(error))
        self.assertIn("🚫", str(error))

    def test_none_error_message(self):
        """Test handling of None error message"""
        try:
            error = TACError(None, TACErrorCodes.DOMAIN_REQUIRED)
            # Should handle gracefully
            self.assertIsNotNone(str(error))
        except TypeError:
            # It's also acceptable to raise TypeError for None message
            pass

    def test_numeric_error_codes(self):
        """Test handling of numeric error codes"""
        # Some systems might use numeric codes
        error = TACError("Test error", 500)

        self.assertEqual(error.code, 500)
        self.assertEqual(str(error), "Test error")

    def test_error_comparison(self):
        """Test error comparison and equality"""
        error1 = TACValidationError("Test", TACErrorCodes.INVALID_DOMAIN)
        error2 = TACValidationError("Test", TACErrorCodes.INVALID_DOMAIN)
        error3 = TACValidationError("Different", TACErrorCodes.INVALID_DOMAIN)

        # Errors should be equal if they have same message and code
        self.assertEqual(str(error1), str(error2))
        self.assertEqual(error1.code, error2.code)

        # Different messages should result in different string representations
        self.assertNotEqual(str(error1), str(error3))


class TestConcurrentErrorHandling(unittest.TestCase):
    """Test error handling under concurrent conditions"""

    def test_concurrent_error_creation(self):
        """Test concurrent error creation doesn't cause issues"""
        import threading
        import time

        errors = []

        def create_errors():
            for i in range(100):
                error = TACNetworkError(f"Error {i}", TACErrorCodes.NETWORK_TIMEOUT)
                errors.append(error)
                time.sleep(0.001)  # Small delay

        # Create errors concurrently
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=create_errors)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All errors should be properly created
        self.assertEqual(len(errors), 500)
        for error in errors:
            self.assertIsInstance(error, TACNetworkError)
            self.assertEqual(error.code, TACErrorCodes.NETWORK_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
