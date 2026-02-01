import { KeyObject } from "node:crypto";

// Schema types - defined locally for now
// TODO: Import from canonical schema when available

// Basic schema types
export interface Email {
  address: string;
  verified?: boolean;
}

export interface Phone {
  number: string;
  verified?: boolean;
}

export interface Verification {
  method: string;
  verified: boolean;
  timestamp?: string;
}

export interface Address {
  street: string;
  city: string;
  state?: string;
  country: string;
  postalCode?: string;
}

export interface Size {
  width?: number;
  height?: number;
  depth?: number;
  weight?: number;
}

export interface ShippingMethod {
  id: string;
  name: string;
  cost: number;
  estimatedDays?: number;
}

export interface Preferences {
  notifications?: boolean;
  marketing?: boolean;
  [key: string]: any;
}

export interface Item {
  id: string;
  name: string;
  price: number;
  quantity?: number;
  category?: string;
}

export interface CartItem extends Item {
  quantity: number;
  subtotal: number;
}

export interface TokenizedCard {
  token: string;
  last4: string;
  brand: string;
  expiryMonth: number;
  expiryYear: number;
}

export interface PaymentMethod {
  type: "card" | "bank" | "wallet";
  tokenizedCard?: TokenizedCard;
  [key: string]: any;
}

export interface Loyalty {
  program: string;
  points?: number;
  tier?: string;
}

export interface User {
  id?: string;
  email?: Email;
  phone?: Phone;
  address?: Address;
  preferences?: Preferences;
  loyalty?: Loyalty;
}

export interface Order {
  id: string;
  items: CartItem[];
  total: number;
  currency: string;
  user?: User;
  shippingMethod?: ShippingMethod;
  paymentMethod?: PaymentMethod;
}

export interface Session {
  id?: string;
  userId?: string;
  timestamp?: string;
  [key: string]: any;
}

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
  kty: string;
  /** Key ID */
  kid?: string;
  /** Algorithm */
  alg?: string;
  /** Key use (sig, enc) */
  use?: "sig" | "enc";
  /** RSA modulus */
  n?: string;
  /** RSA exponent */
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
  user?: User;
  /** Order/transaction information */
  order?: Order;
  /** Session context and tracking */
  session?: Session;
  /** Standalone items (not necessarily in cart) */
  items?: Item[];
  /** Updates, webhooks and endpoints for async events */
  notifications?: any[];
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
