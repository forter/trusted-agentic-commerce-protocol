/**
 * Trusted Agentic Commerce Protocol SDK
 *
 * Secure authentication and data encryption for AI agents
 * Implements HTTP Message Signatures (RFC 9421) and JWE encryption
 */

// Primary exports - recommended usage
export { default as TACSender } from "./sender.js";
export { default as TACRecipient } from "./recipient.js";

// Utility exports for advanced usage
export {
  JWKSCache,
  fetchJWKSWithRetry,
  jwkToPublicKey,
  getKeyAlgorithm,
  signData,
  verifySignature,
  generateKeyId,
  findMatchingKey,
  findEncryptionKey,
  findSigningKey,
  derivePublicKey,
} from "./utils.js";
