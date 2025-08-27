import { KeyObject } from 'node:crypto';

// Import ALL schema types from the canonical source
export * from '../../schema/2025-08-27/schema.js';
import type * as Schema from '../../schema/2025-08-27/schema.js';

/**
 * JWKS structure
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * Cached JWKS structure
 */
export interface CachedJWKS {
  keys: JWK[];
  expires: number;
}

/**
 * JWK (JSON Web Key) structure for representing cryptographic keys
 */
export interface JWK {
  /** Key type */
  kty: 'RSA' | 'EC' | 'OKP';
  /** Key ID */
  kid?: string;
  /** Algorithm */
  alg?: string;
  /** Key use (sig, enc) */
  use?: 'sig' | 'enc';
  /** Curve (for EC and OKP keys) */
  crv?: string;
  /** X coordinate (for EC and OKP keys) */
  x?: string;
  /** Y coordinate (for EC keys) */
  y?: string;
  /** RSA modulus (for RSA keys) */
  n?: string;
  /** RSA exponent (for RSA keys) */
  e?: string;
  /** Not before timestamp */
  nbf?: number;
  /** Expiration timestamp */
  exp?: number;
}

/**
 * Sender configuration options
 */
export interface SenderOptions {
  /** Domain of the agent */
  domain: string;
  /** Private key for signing (RSA) */
  privateKey: KeyObject | string;
  /** JWT TTL in seconds */
  ttl?: number;
  /** JWKS cache timeout in ms */
  cacheTimeout?: number;
  /** Max retry attempts */
  maxRetries?: number;
  /** Retry delay in ms */
  retryDelay?: number;
}

/**
 * Recipient configuration options
 */
export interface RecipientOptions {
  /** Domain of the recipient */
  domain: string;
  /** Private key for decryption (RSA) */
  privateKey: KeyObject | string;
  /** JWKS cache timeout in ms */
  cacheTimeout?: number;
  /** Max retry attempts */
  maxRetries?: number;
  /** Retry delay in ms */
  retryDelay?: number;
}

/**
 * Fetch options for JWKS
 */
export interface FetchOptions {
  cache?: any;
  maxRetries?: number;
  initialDelay?: number;
  maxDelay?: number;
  userAgent?: string;
  forceRefresh?: boolean;
}

/**
 * Processing result from recipient
 */
export interface ProcessingResult {
  valid: boolean;
  issuer: string | null;
  expires: Date | null;
  data: any;
  recipients: string[];
  errors: string[];
}

/**
 * User data structure for encryption - flexible data format
 */
export interface Recipient {
  /** User information and account details */
  user?: Schema.User;
  /** Order/transaction information */
  order?: Schema.Order;
  /** Session context and tracking */
  session?: Schema.Session;
  /** Standalone items (not necessarily in cart) */
  items?: Schema.Item[];
  /** Updates, webhooks and endpoints for async events */
  notifications?: Schema.Notification[];
  /** Custom fields for extensibility */
  custom?: Record<string, any>;
  /** Allow any other properties for flexibility */
  [key: string]: any;
}

/**
 * Recipients data structure
 */
export interface Recipients {
  [domain: string]: Recipient;
}

// Type aliases for backward compatibility
export type UserData = Recipient;
export type RecipientsData = Recipients;