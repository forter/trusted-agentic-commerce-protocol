/**
 * Trusted Agentic Commerce Protocol TypeScript SDK
 *
 * Secure authentication and data encryption for AI agents
 * Implements JWS+JWE for signing and encryption with multi-recipient messages
 */

// Primary exports - recommended usage
export { default as TACSender } from "./sender.js";
export { default as TACRecipient } from "./recipient.js";

// Error exports for better error handling
export {
  TACError,
  TACValidationError,
  TACNetworkError,
  TACCryptoError,
  TACMessageError,
  TACErrorCodes,
} from "./errors.js";

// Version exports
export { SCHEMA_VERSION, SDK_VERSION, SDK_LANGUAGE } from "./version.js";

// Utility exports for advanced usage
export {
  JWKSCache,
  fetchJWKSWithRetry,
  findEncryptionKey,
  findSigningKey,
  getKeyType,
  getAlgorithmForKey,
  publicKeyToJWK,
  getUserAgent,
} from "./utils.js";

// Type exports
export type { JWK, FetchOptions } from "./utils.js";
export type { SenderOptions, Recipients } from "./sender.js";
export type { RecipientOptions, ProcessingResult } from "./recipient.js";
