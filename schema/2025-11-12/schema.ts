/**
 * Trusted Agentic Commerce Protocol - Data Schema
 * Version: 2025-11-12
 * 
 * A comprehensive JSON schema for securely exchanging encrypted data
 * between parties using the Trusted Agentic Commerce Protocol.
 */

export interface Session {
  /** Session ID */
  id?: string;
  /** Communication channel */
  channel?: 
    | 'WEB'
    | 'MOBILE'
    | 'CHAT'
    | 'VOICE'
    | 'API'
    | 'OTHER';
  /** Traffic source */
  source?: string;
  /** Traffic medium (e.g., email, cpc, organic) */
  medium?: string;
  /** Campaign identifier */
  campaign?: string;
  /** Referrer URL */
  referrer?: string;
  /** Underlying goal and desired outcome */
  intent?: string;
  /** Explicit/implicit permission to take specific action */
  consent?: string;
  /** IP address */
  ipAddress?: string;
  /** User agent string */
  userAgent?: string;
  /** Session creation date, if not the current time */
  created?: string;
  /** Vendor-specific keys for additional session data */
  [vendorKey: string]: string | undefined;
}

export interface User {
  /** User ID in the agent system */
  id?: string;
  /** User ID in the merchant system */
  merchantId?: string;
  /** User email information */
  email?: Email;
  /** User phone information */
  phone?: Phone;
  /** User preferences for personalization */
  preferences?: Preferences;
  /** Loyalty programs */
  loyalties?: Loyalty[];
  /** Payment methods */
  paymentMethods?: PaymentMethod[];
  /** User addresses */
  addresses?: Address[];
  /** Account creation date */
  created?: string; // ISO 8601 timestamp
  /** Last login date */
  lastLogin?: string; // ISO 8601 timestamp
  /** Account status */
  status?:
    | 'ACTIVE'
    | 'SUSPENDED'
    | 'PENDING_VERIFICATION'
    | 'CLOSED'
    | 'OTHER';
  /** Account type */
  type?:
    | 'INDIVIDUAL'
    | 'BUSINESS'
    | 'PREMIUM'
    | 'OTHER';
}

export interface Verification {
  /** Method used for verification */
  method: 
    | 'MAGIC_LINK'
    | 'EMAIL_OTP'
    | 'SMS_OTP'
    | 'PHONE_CALL'
    | 'SOCIAL_LOGIN_GOOGLE'
    | 'SOCIAL_LOGIN_FACEBOOK'
    | 'SOCIAL_LOGIN_APPLE'
    | 'SOCIAL_LOGIN_MICROSOFT'
    | 'AUTHENTICATOR_APP'
    | 'PASSKEYS'
    | 'BIOMETRIC'
    | 'DOCUMENT'
    | 'VOICE'
    | 'OTHER';
  /** Timestamp when the information was verified */
  at: string; // ISO 8601 timestamp
}

export interface Email {
  /** Email address */
  address: string;
  /** Verification information if available */
  verifications?: Verification[];
}

export interface Phone {
  /** Phone number */
  number: string; // in E.164 format (+14155550123)
  /** Type of phone number */
  type?: 
    | 'MOBILE'
    | 'LANDLINE'
    | 'VOIP'
    | 'OTHER';
  /** Verification information if available */
  verifications?: Verification[];
}

export interface Address {
  /** Full name for this address */
  name?: string;
  /** Company name if applicable */
  company?: string;
  /** Address line 1 */
  line1: string;
  /** Address line 2 (apartment, suite, etc.) */
  line2?: string;
  /** City */
  city: string;
  /** State/Region/Province */
  region: string;
  /** Postal/ZIP code */
  postal: string;
  /** Country code (ISO 3166-1 alpha-2) */
  country: string;
  /** Geocoding information if available */
  coordinates?: {
    latitude: number;
    longitude: number;
  };
  /** Address type */
  type?: 
    | 'RESIDENTIAL'
    | 'COMMERCIAL'
    | 'POB'
    | 'HOTEL'
    | 'FORWARDER'
    | 'RESHIPPER'
    | 'WAREHOUSE'
    | 'MILITARY'
    | 'TEMPORARY'
    | 'OTHER';
}

export interface Size {
  /** The size value */
  value: any;
  /** Unit of measurement if applicable */
  unit?: string;
  /** How this size was determined */
  method?:
    | 'HISTORICAL_PURCHASE'
    | 'USER_INPUT'
    | 'INFERRED'
    | 'SURVEY'
    | 'BEHAVIORAL'
    | 'OTHER';
  /** When this size was last used, recorded or measured */
  at?: string; // ISO 8601 timestamp
  /** Confidence level (0-1) */
  confidence?: number;
}

export interface ShippingMethod {
  /** Shipping method type */
  type:
    | 'STANDARD'
    | 'EXPRESS'
    | 'OVERNIGHT'
    | 'SAME_DAY'
    | 'IN_STORE_PICKUP'
    | 'LOCKER_PICKUP'
    | 'CURBSIDE'
    | 'DRONE'
    | 'OTHER';
}

export interface Preferences {
  /** Preferred brands */
  brands?: string[];
  /** Preferred colors */
  colors?: string[];
  /** Size preferences for various categories */
  sizes?: Record<string, Size>;
  /** Language preferences */
  languages?: string[]; // ISO 639-1 codes
  /** Preferred currencies */
  currencies?: string[]; // ISO 4217 codes
  /** Communication preferences */
  communication?: {
    email?: boolean;
    sms?: boolean;
    push?: boolean;
    frequency?: 
      | 'DAILY'
      | 'WEEKLY'
      | 'MONTHLY'
      | 'NEVER'
      | 'OTHER';
  };
  /** Delivery time preferences */
  deliveryTimes?: (
    | 'MORNING'
    | 'AFTERNOON'
    | 'EVENING'
    | 'WEEKEND'
    | 'OTHER'
  )[];
  /** Shipping method preferences */
  shippingMethods?: ShippingMethod[];
  /** Flight preferences */
  flight?: {
    /** Origin airport or city */
    origin?: string; // Airport code (e.g., "LAX") or city name
    /** Destination airport or city */
    destination?: string; // Airport code (e.g., "JFK") or city name
    /** Departure date */
    departure?: string; // ISO 8601 date
    /** Return date */
    return?: string; // ISO 8601 date
    /** Typical passenger breakdown the user travels or books for */
    passengers?: {
      /** Number of adults (usually age 12+) */
      adults?: number;
      /** Number of children (usually ages 2-11) */
      children?: number;
      /** Number of infants (usually under 2 years) */
      infants?: number;
    };
    /** Preferred airlines */
    airlines?: string[];
    /** Preferred departure times */
    departureTimes?: (
      | 'EARLY_MORNING'
      | 'MORNING'
      | 'AFTERNOON'
      | 'EVENING'
      | 'LATE_NIGHT'
      | 'RED_EYE'
    )[];
    /** Preferred arrival times */
    arrivalTimes?: (
      | 'EARLY_MORNING'
      | 'MORNING'
      | 'AFTERNOON'
      | 'EVENING'
      | 'LATE_NIGHT'
      | 'RED_EYE'
    )[];
    /** Maximum number of stops */
    maxStops?: number;
    /** Preferred cabin class */
    classes?: (
      | 'ECONOMY'
      | 'PREMIUM_ECONOMY'
      | 'BUSINESS'
      | 'FIRST'
      | 'OTHER'
    )[];
    /** Preferred seat type */
    seats?: (
      | 'AISLE'
      | 'WINDOW'
      | 'MIDDLE'
      | 'EXIT_ROW'
      | 'OTHER'
    )[];
    /** Preferred meals */
    meals?: (
      | 'VEGETARIAN'
      | 'VEGAN'
      | 'KOSHER'
      | 'HALAL'
      | 'GLUTEN_FREE'
      | 'DIABETIC'
      | 'LOW_SODIUM'
      | 'CHILD'
      | 'INFANT'
      | 'OTHER'
    )[];
    /** Special service requests */
    services?: (
      | 'WHEELCHAIR'
      | 'MEDICAL_EQUIPMENT'
      | 'UNACCOMPANIED_MINOR'
      | 'PET_TRAVEL'
      | 'LOUNGE_ACCESS'
      | 'OTHER'
    )[];
    /** Special requests or instructions */
    specialRequests?: string[];
  };

  /** Hotel preferences */
  hotel?: {
    /** Airport code (e.g., "JFK") or city name */
    location?: string;
    /** Check-in date */
    checkIn?: string; // ISO 8601 date
    /** Check-out date */
    checkOut?: string; // ISO 8601 date
    /** Typical guest breakdown the user books for */
    guests?: {
      /** Number of adults */
      adults?: number;
      /** Number of children */
      children?: number;
      /** Number of infants */
      infants?: number;
    };
    /** Preferred hotel brands */
    brands?: string[];
    /** Preferred room type */
    roomTypes?: (
      | 'STANDARD'
      | 'FAMILY'
      | 'APARTMENT'
      | 'VILLA'
      | 'SUITE'
      | 'OTHER'
    )[];
    /** Number of rooms */
    rooms?: number;
    /** Preferred bed type */
    bedTypes?: (
      | 'KING'
      | 'QUEEN'
      | 'DOUBLE'
      | 'TWIN'
      | 'SINGLE'
      | 'SOFA_BED'
      | 'BUNK'
      | 'OTHER'
    )[];
    /** Accessibility requirements */
    accessibilities?: (
      | 'WHEELCHAIR_ACCESSIBLE'
      | 'HEARING_IMPAIRED'
      | 'VISUALLY_IMPAIRED'
      | 'SERVICE_ANIMAL'
      | 'OTHER'
    )[];
    /** Amenities preferences */
    amenities?: (
      | 'WIFI'
      | 'BREAKFAST_INCLUDED'
      | 'GYM'
      | 'POOL'
      | 'SPA'
      | 'PARKING'
      | 'AIR_CONDITIONING'
      | 'KITCHEN'
      | 'PET_FRIENDLY'
      | 'EV_CHARGING'
      | 'RESTAURANT'
      | 'BAR'
      | 'LAUNDRY'
      | 'OTHER'
    )[];
    /** Special service requests */
    services?: (
      | 'EARLY_CHECKIN'
      | 'LATE_CHECKIN'
      | 'LATE_CHECKOUT'
      | 'HIGH_FLOOR'
      | 'QUIET_ROOM'
      | 'SMOKING_ROOM'
      | 'NON_SMOKING_ROOM'
      | 'CONNECTING_ROOMS'
      | 'WHEELCHAIR_ACCESSIBLE'
      | 'EXTRA_PILLOWS'
      | 'CRIB'
      | 'ROLLAWAY_BED'
      | 'BREAKFAST_INCLUDED'
      | 'FRONT_DESK'
      | 'HOUSEKEEPING'
      | 'CONCIERGE'
      | 'ROOM_SERVICE'
      | 'LUGGAGE_STORAGE'
      | 'LAUNDRY'
      | 'DRY_CLEANING'
      | 'SHUTTLE'
      | 'VALET'
      | 'PET_FRIENDLY'
      | 'BABYSITTING'
      | 'CAR_RENTAL'
      | 'PRINTING'
      | 'PACKAGE_RECEIVING'
      | 'OTHER'
    )[];
    /** Special requests or instructions */
    specialRequests?: string[];
  };

  /** Car rental preferences */
  carRental?: {
    /** Primary driver age range */
    primaryDriverAge?:
      | 'UNDER_25'
      | '25_64'
      | '65_PLUS';
    /** Number of additional drivers */
    additionalDrivers?: number;
    /** Preferred car rental companies */
    companies?: string[];
    /** Preferred vehicle categories */
    categories?: (
      | 'ECONOMY'
      | 'COMPACT'
      | 'MIDSIZE'
      | 'FULLSIZE'
      | 'PREMIUM'
      | 'LUXURY'
      | 'SUV'
      | 'MINIVAN'
      | 'PICKUP'
      | 'CONVERTIBLE'
      | 'SPORTS'
      | 'ELECTRIC'
      | 'HYBRID'
      | 'OTHER'
    )[];
    /** Preferred transmission type */
    transmission?:
      | 'AUTOMATIC'
      | 'MANUAL';
    /** Fuel type preferences */
    fuelTypes?: (
      | 'GASOLINE'
      | 'DIESEL'
      | 'ELECTRIC'
      | 'HYBRID'
      | 'PLUG_IN_HYBRID'
      | 'HYDROGEN'
      | 'OTHER'
    )[];
    /** Preferred pickup locations */
    pickupLocations?: (
      | 'AIRPORT'
      | 'HOTEL'
      | 'CITY_CENTER'
      | 'TRAIN_STATION'
      | 'RENTAL_OFFICE'
      | 'OTHER'
    )[];
    /** Insurance preferences */
    insurance?: (
      | 'CDW'
      | 'SCDW'
      | 'TP'
      | 'STP'
      | 'LI'
      | 'PAI'
      | 'PEC'
      | 'SLI'
      | 'OTHER'
    )[];
    /** Accessibility requirements */
    accessibilities?: (
      | 'HAND_CONTROLS'
      | 'WHEELCHAIR_ACCESSIBLE'
      | 'SWIVEL_SEAT'
      | 'SPINNER_KNOB'
      | 'LEFT_FOOT_ACCELERATOR'
      | 'OTHER'
    )[];
    /** Special equipment, add-ones and service preferences */
    services?: (
      | 'GPS_NAVIGATION'
      | 'WIFI_HOTSPOT'
      | 'CHILD_SEAT'
      | 'BOOSTER_SEAT'
      | 'INFANT_SEAT'
      | 'SKI_RACK'
      | 'BIKE_RACK'
      | 'ROOF_BOX'
      | 'SNOW_CHAINS'
      | 'ROADSIDE_ASSISTANCE'
      | 'ONE_WAY_RENTAL'
      | 'LONG_TERM_RENTAL'
      | 'CORPORATE_RATE'
      | 'LOYALTY_PROGRAM'
      | 'MOBILE_CHECKIN'
      | 'KEYLESS_ENTRY'
      | 'CONTACTLESS_PICKUP'
      | 'VEHICLE_SANITIZATION'
      | 'FUEL_PREPURCHASE'
      | 'RETURN_REFUEL_SERVICE'
      | 'UNLIMITED_MILEAGE'
      | 'OTHER'
    )[];
    /** Special requests or instructions */
    specialRequests?: string[];
  };
}

export interface Item {
  /** Item identifier (either id or sku is required) */
  id?: string;
  /** Stock Keeping Unit identifier (either id or sku is required) */
  sku?: string;
  /** Product name */
  name?: string;
  /** Product description */
  description?: string;
  /** Product category */
  category?: string;
  /** Product brand */
  brand?: string;
  /** Product URL */
  url?: string;
  /** Product image URL */
  imageUrl?: string;
  /** Product attributes (size, color, etc.) */
  attributes?: Record<string, string>;
  /** Unit price */
  price?: number;
  /** Product availability */
  availability?:
    | 'IN_STOCK'
    | 'OUT_OF_STOCK'
    | 'PREORDER'
    | 'BACKORDER'
    | 'OTHER';
  /** Product rating */
  rating?: number;
  /** Product reviews */
  reviews?: {
    /** Number of reviews */
    count: number;
    /** Average rating */
    average: number;
  };
}

export interface CartItem extends Item {
  /** Quantity */
  quantity: number;
  /** Unit price */
  price: number;
}

export interface TokenizedCard {
  /** Card type */
  type?:
    | 'CREDIT'
    | 'DEBIT'
    | 'PREPAID'
    | 'OTHER';
  /** Card brand */
  brand?:
    | 'VISA'
    | 'MASTERCARD'
    | 'AMEX'
    | 'DISCOVER'
    | 'JCB'
    | 'DINERS'
    | 'UNIONPAY'
    | 'OTHER';
  /** Token provider */
  provider?: string;
  /** Payment token */
  token: string;
  /** Expiration month (1-12) */
  expiryMonth?: number;
  /** Expiration year */
  expiryYear?: number;
  /** Last 4 digits of the card */
  last4?: number;
  /** Cardholder name */
  holderName?: string;
  /** Billing address associated with the card */
  billingAddress?: Address;
}

export interface PaymentMethod {
  /** Type of payment method */
  type:
    | 'CARD'
    | 'BANK_ACCOUNT'
    | 'DIGITAL_WALLET'
    | 'CRYPTOCURRENCY'
    | 'BNPL'
    | 'OTHER';
  /** Tokenized card information if type is CARD */
  card?: TokenizedCard;
  /** Bank account information (tokenized) */
  bankAccount?: {
    accountType?:
      | 'CHECKING'
      | 'SAVINGS'
      | 'OTHER';
    bankName?: string;
    last4?: string;
    token: string;
  };
  /** Digital wallet information */
  digitalWallet?: {
    provider:
      | 'APPLE_PAY'
      | 'GOOGLE_PAY'
      | 'PAYPAL'
      | 'AMAZON_PAY'
      | 'SAMSUNG_PAY'
      | 'VENMO'
      | 'ALIPAY'
      | 'WECHAT_PAY'
      | 'CASH_APP'
      | 'SKRILL'
      | 'NETELLER'
      | 'LINE_PAY'
      | 'GRABPAY'
      | 'GCASH'
      | 'REVOLUT'
      | 'ZELLE'
      | 'OTHER';
    token?: string;
  };
  /** Crypto currency information */
  cryptoCurrency?: {
    provider:
      | 'BITCOIN'
      | 'ETHEREUM'
      | 'XRP'
      | 'TETHER'
      | 'SOLANA'
      | 'USDC'
      | 'OTHER';
    token?: string;
  };
  /** Buy now, pay later options */
  bnpl?: {
    provider:
      | 'KLARNA'
      | 'AFTERPAY'
      | 'AFFIRM'
      | 'SEZZLE'
      | 'ZIP'
      | 'OTHER';
    token?: string;
  };
  /** Payment method creation date */
  created?: string; // ISO 8601 timestamp
}

export interface Loyalty {
  /** Loyalty program identifier */
  programId: string;
  /** Member ID in the loyalty program */
  memberId: string;
  /** Current points/miles balance */
  balance?: number;
  /** Tier/status level */
  tier?: string;
  /** Points to be used for this transaction */
  pointsToRedeem?: number;
}

export interface Order {
  /** Order ID */
  id?: string;
  /** Items in cart */
  cart?: CartItem[];
  /** Subtotal before shipping and tax */
  subtotal?: number;
  /** Shipping cost */
  shipping?: number;
  /** Tax amount */
  tax?: number;
  /** Applied discounts */
  discounts?: {
    amount: number;
    type: 
      | 'FIXED'
      | 'PERCENTAGE';
    code?: string;
  };
  /** Order total amount */
  total?: number;
  /** Billing address */
  billingAddress?: Address;
  /** Shipping address */
  shippingAddress?: Address;
  /** Shipping method */
  shippingMethod?: ShippingMethod;
  /** Selected payment method for this order */
  paymentMethod?: PaymentMethod;
  /** Order currency */
  currency?: string; // ISO 4217
  /** Order type */
  type?:
    | 'PURCHASE'
    | 'REFUND'
    | 'AUTHORIZATION'
    | 'CAPTURE'
    | 'OTHER';
  /** Order timestamp */
  created?: string; // ISO 8601 timestamp
}

export interface Notification {
  /** Notification ID */
  id?: string;
  
  /** Events to receive notifications for */
  events: (
    | 'ITEM_STATUS'
    | 'ORDER_STATUS'
    | 'PAYMENT_STATUS'
    | 'SHIPPING_STATUS'
    | 'DISPUTE_STATUS'
    | 'OTHER'
  )[];

  type:
    | 'URL'
    | 'EMAIL'
    | 'SMS'
    | 'PUSH'
    | 'CALL'
    | 'SLACK'
    | 'WHATSAPP'
    | 'TELEGRAM'
    | 'OTHER';
  
  /** URL, phone number, email, chat ID, etc. */
  target: string;
}

export interface Callback {
  /** The callback URL */
  url: string;
  /** Events this URL should receive */
  events: (
    | 'CART_STATUS'
    | 'ORDER_STATUS'
    | 'PAYMENT_STATUS'
    | 'SHIPPING_STATUS'
    | 'DISPUTE_STATUS'
    | 'OTHER'
  )[];
}

/**
 * Main schema for encrypted data exchange in Agent Auth Protocol
 */
export interface Recipient {  
  /** Session context and tracking */
  session?: Session;
  
  /** User information and account details */
  user?: User;
  
  /** Requested items (not necessarily in cart) */
  items?: Item[];
  
  /** Order/transaction information */
  order?: Order;
  
  /** Updates, webhooks and endpoints for async events */
  notifications?: Notification[];
  
  /** Custom fields for extensibility */
  custom?: Record<string, any>;
}

/**
 * Container for all encrypted recipient data
 */
export interface EncryptedDataContainer {
  /** Version of the encryption format */
  version: '2025-11-12';
  /** Object mapping recipient domains to their encrypted data */
  recipients: Record<string, Partial<Recipient>>;
}

/**
 * Root schema structure matching the JSON schema format
 * This is used for generating the JSON schema file
 */
export interface SchemaRoot {
  /** Version of the schema */
  schemaVersion: '2025-11-12';
  /** User information and account details */
  user?: User;
  /** Order/transaction information */
  order?: Order;
  /** Session context and tracking */
  session?: Session;
  /** Standalone items (not necessarily in cart) */
  items?: Item[];
  /** Callback URLs for async events */
  callbacks?: Callback[];
  /** Custom fields for extensibility */
  custom?: Record<string, any>;
}
