/**
 * TAC Protocol Error Classes
 * Provides specific error types with error codes for better error handling
 */

/**
 * Base TAC Protocol Error
 */
export class TACError extends Error {
  public readonly code: string;

  constructor(message: string, code: string = "TAC_UNKNOWN_ERROR") {
    super(message);
    this.name = "TACError";
    this.code = code;
  }
}

/**
 * Validation/Input Error
 */
export class TACValidationError extends TACError {
  constructor(message: string, code: string = "TAC_VALIDATION_ERROR") {
    super(message, code);
    this.name = "TACValidationError";
  }
}

/**
 * Network/Communication Error
 */
export class TACNetworkError extends TACError {
  constructor(message: string, code: string = "TAC_NETWORK_ERROR") {
    super(message, code);
    this.name = "TACNetworkError";
  }
}

/**
 * Cryptographic Operation Error
 */
export class TACCryptoError extends TACError {
  constructor(message: string, code: string = "TAC_CRYPTO_ERROR") {
    super(message, code);
    this.name = "TACCryptoError";
  }
}

/**
 * Message Processing Error
 */
export class TACMessageError extends TACError {
  constructor(message: string, code: string = "TAC_MESSAGE_ERROR") {
    super(message, code);
    this.name = "TACMessageError";
  }
}

/**
 * Error Codes Enum
 *
 * Use these codes to handle specific error types in your application:
 *
 * @example
 * try {
 *   const sender = new TACSender({ domain: '', privateKey: key });
 * } catch (error) {
 *   if (error.code === TACErrorCodes.DOMAIN_REQUIRED) {
 *     console.log('Please provide a valid domain');
 *   }
 * }
 */
export const TACErrorCodes = {
  // Validation Errors
  DOMAIN_REQUIRED: "TAC_DOMAIN_REQUIRED",
  PRIVATE_KEY_REQUIRED: "TAC_PRIVATE_KEY_REQUIRED",
  INVALID_KEY_DATA: "TAC_INVALID_KEY_DATA",
  UNSUPPORTED_KEY_TYPE: "TAC_UNSUPPORTED_KEY_TYPE",
  NO_PUBLIC_KEY: "TAC_NO_PUBLIC_KEY",
  NO_PRIVATE_KEY: "TAC_NO_PRIVATE_KEY",
  NO_RECIPIENT_DATA: "TAC_NO_RECIPIENT_DATA",

  // Network Errors
  HTTP_ERROR: "TAC_HTTP_ERROR",
  NETWORK_TIMEOUT: "TAC_NETWORK_TIMEOUT",
  JWKS_FETCH_FAILED: "TAC_JWKS_FETCH_FAILED",
  JWKS_PARSE_ERROR: "TAC_JWKS_PARSE_ERROR",
  JWKS_INVALID_FORMAT: "TAC_JWKS_INVALID_FORMAT",
  NO_ENCRYPTION_KEY_FOUND: "TAC_NO_ENCRYPTION_KEY_FOUND",
  NO_SIGNING_KEY_FOUND: "TAC_NO_SIGNING_KEY_FOUND",

  // Message Errors
  INVALID_MESSAGE_FORMAT: "TAC_INVALID_MESSAGE_FORMAT",
  MISSING_RECIPIENTS: "TAC_MISSING_RECIPIENTS",
  NOT_A_RECIPIENT: "TAC_NOT_A_RECIPIENT",
  JWT_MISSING_ISSUER: "TAC_JWT_MISSING_ISSUER",
  JWT_AUDIENCE_MISMATCH: "TAC_JWT_AUDIENCE_MISMATCH",
  JWT_NOT_YET_VALID: "TAC_JWT_NOT_YET_VALID",
  NO_PUBLIC_KEYS_FOUND: "TAC_NO_PUBLIC_KEYS_FOUND",

  // Crypto Errors
  SIGNATURE_VERIFICATION_FAILED: "TAC_SIGNATURE_VERIFICATION_FAILED",
  DECRYPTION_FAILED: "TAC_DECRYPTION_FAILED",
  ENCRYPTION_FAILED: "TAC_ENCRYPTION_FAILED",
  JWT_SIGNING_FAILED: "TAC_JWT_SIGNING_FAILED",
  JWK_IMPORT_FAILED: "TAC_JWK_IMPORT_FAILED",
  JWK_EXPORT_FAILED: "TAC_JWK_EXPORT_FAILED",
  JWT_DECODE_FAILED: "TAC_JWT_DECODE_FAILED",
} as const;
