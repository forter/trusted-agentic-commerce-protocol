/**
 * Trusted Agentic Commerce Protocol TypeScript SDK
 *
 * Secure authentication and data encryption for AI agents
 * Implements JWT signing and JWE encryption for multi-recipient messages
 */

// Primary exports - recommended usage
export { default as TACSender } from "./sender.js";
export { default as TACRecipient } from "./recipient.js";

// Utility exports for advanced usage
export {
  JWKSCache,
  fetchJWKSWithRetry,
  generateKeyId,
  findEncryptionKey,
  findSigningKey,
  isRSAKey,
} from "./utils.js";

// Type exports - now using canonical schema types
export type {
  JWK,
  JWKS,
  SenderOptions,
  RecipientOptions,
  FetchOptions,
  ProcessingResult,
  UserData,
  RecipientsData,
  // All schema types are re-exported from sdk-types.ts
  Email,
  Phone,
  Verification,
  Address,
  Size,
  ShippingMethod,
  Preferences,
  Item,
  CartItem,
  TokenizedCard,
  PaymentMethod,
  Loyalty,
  User,
  Order,
  Session,
} from "./sdk-types.js";
