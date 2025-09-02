"""
TAC Protocol Error Classes
Provides specific error types with error codes for better error handling
"""


class TACError(Exception):
    """Base TAC Protocol Error"""

    def __init__(self, message: str, code: str = "TAC_UNKNOWN_ERROR"):
        super().__init__(message)
        self.message = message
        self.code = code


class TACValidationError(TACError):
    """Validation/Input Error"""

    def __init__(self, message: str, code: str = "TAC_VALIDATION_ERROR"):
        super().__init__(message, code)


class TACNetworkError(TACError):
    """Network/Communication Error"""

    def __init__(self, message: str, code: str = "TAC_NETWORK_ERROR"):
        super().__init__(message, code)


class TACCryptoError(TACError):
    """Cryptographic Operation Error"""

    def __init__(self, message: str, code: str = "TAC_CRYPTO_ERROR"):
        super().__init__(message, code)


class TACMessageError(TACError):
    """Message Processing Error"""

    def __init__(self, message: str, code: str = "TAC_MESSAGE_ERROR"):
        super().__init__(message, code)


class TACErrorCodes:
    """
    Error Codes Enum

    Use these codes to handle specific error types in your application:

    Example:
        try:
            sender = TACSender(domain='', private_key=key)
        except TACError as error:
            if error.code == TACErrorCodes.DOMAIN_REQUIRED:
                print('Please provide a valid domain')
    """

    # Validation Errors
    DOMAIN_REQUIRED = "TAC_DOMAIN_REQUIRED"
    INVALID_DOMAIN = "TAC_INVALID_DOMAIN"
    PRIVATE_KEY_REQUIRED = "TAC_PRIVATE_KEY_REQUIRED"
    INVALID_KEY_DATA = "TAC_INVALID_KEY_DATA"
    INVALID_DATA = "TAC_INVALID_DATA"
    UNSUPPORTED_KEY_TYPE = "TAC_UNSUPPORTED_KEY_TYPE"
    NO_PUBLIC_KEY = "TAC_NO_PUBLIC_KEY"
    NO_PRIVATE_KEY = "TAC_NO_PRIVATE_KEY"
    NO_RECIPIENT_DATA = "TAC_NO_RECIPIENT_DATA"

    # Network Errors
    HTTP_ERROR = "TAC_HTTP_ERROR"
    NETWORK_TIMEOUT = "TAC_NETWORK_TIMEOUT"
    JWKS_FETCH_FAILED = "TAC_JWKS_FETCH_FAILED"
    JWKS_PARSE_ERROR = "TAC_JWKS_PARSE_ERROR"
    JWKS_INVALID_FORMAT = "TAC_JWKS_INVALID_FORMAT"
    NO_ENCRYPTION_KEY_FOUND = "TAC_NO_ENCRYPTION_KEY_FOUND"
    NO_SIGNING_KEY_FOUND = "TAC_NO_SIGNING_KEY_FOUND"

    # Message Errors
    INVALID_MESSAGE_FORMAT = "TAC_INVALID_MESSAGE_FORMAT"
    MISSING_RECIPIENTS = "TAC_MISSING_RECIPIENTS"
    NOT_A_RECIPIENT = "TAC_NOT_A_RECIPIENT"
    JWT_MISSING_ISSUER = "TAC_JWT_MISSING_ISSUER"
    JWT_AUDIENCE_MISMATCH = "TAC_JWT_AUDIENCE_MISMATCH"
    JWT_NOT_YET_VALID = "TAC_JWT_NOT_YET_VALID"
    NO_PUBLIC_KEYS_FOUND = "TAC_NO_PUBLIC_KEYS_FOUND"

    # Crypto Errors
    SIGNATURE_VERIFICATION_FAILED = "TAC_SIGNATURE_VERIFICATION_FAILED"
    DECRYPTION_FAILED = "TAC_DECRYPTION_FAILED"
    ENCRYPTION_FAILED = "TAC_ENCRYPTION_FAILED"
    JWT_SIGNING_FAILED = "TAC_JWT_SIGNING_FAILED"
    JWT_VERIFICATION_FAILED = "TAC_JWT_VERIFICATION_FAILED"
    JWK_IMPORT_FAILED = "TAC_JWK_IMPORT_FAILED"
    JWK_EXPORT_FAILED = "TAC_JWK_EXPORT_FAILED"
    JWT_DECODE_FAILED = "TAC_JWT_DECODE_FAILED"

    # Additional Message Errors
    MESSAGE_EXPIRED = "TAC_MESSAGE_EXPIRED"
    INVALID_SIGNATURE = "TAC_INVALID_SIGNATURE"
