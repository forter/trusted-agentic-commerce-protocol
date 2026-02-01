# Trusted Agentic Commerce Protocol JavaScript SDK

JavaScript SDK implementing the [Trusted Agentic Commerce Protocol,](https://www.forter.com/blog/proposing-a-trusted-agentic-commerce-protocol/) allowing merchants and agent developers to:

- ✅ Authenticate each other: verify the agent's identity and its relationship to the customer behind it
- ✅ Maintain rich customer data: reduce data losses experienced by merchants and increase agents approval rate
- ✅ Improve user experience: create personalized, secure and frictionless checkout experience
- ✅ Prevent fraud: differentiates between legitimate agentic activity and fraud attempts

## Getting Started

- [Trusted Agentic Commerce Protocol JavaScript SDK](#trusted-agentic-commerce-protocol-javascript-sdk)
  - [Getting Started](#getting-started)
  - [Basic Usage](#basic-usage)
    - [For Senders (AI Agents)](#for-senders-ai-agents)
    - [For Recipients (Merchants)](#for-recipients-merchants)
  - [Advanced Usage](#advanced-usage)
    - [Using Password-Protected Private Keys](#using-password-protected-private-keys)
    - [Collecting Vendor-Specific Data](#collecting-vendor-specific-data)
      - [Example: Forter Integration](#example-forter-integration)
    - [Sending to Multiple Recipients](#sending-to-multiple-recipients)
    - [Setting Up Callbacks and Notifications](#setting-up-callbacks-and-notifications)
  - [Express.js Integration](#expressjs-integration)
  - [Manual JWKS Management](#manual-jwks-management)
  - [Command Line Interface](#command-line-interface)
    - [Installation](#installation)
    - [tacp-send](#tacp-send)
    - [tacp-receive](#tacp-receive)
    - [Exit Codes](#exit-codes)
  - [Development](#development)
    - [Installation](#installation-1)
    - [Running Tests](#running-tests)
    - [Test Suites](#test-suites)
    - [Linting \& Formatting](#linting--formatting)
  - [API Reference](#api-reference)
    - [TACSender](#tacsender)
      - [Constructor Options](#constructor-options)
      - [Methods](#methods)
    - [TACRecipient](#tacrecipient)
      - [Constructor Options](#constructor-options-1)
      - [Methods](#methods-1)
      - [Static Methods](#static-methods)
  - [Features](#features)
  - [Requirements](#requirements)

## Basic Usage

### For Senders (AI Agents)

```javascript
import TACSender from './sender.js';

// Get private key from env, vault or secret manager
const agentPrivateKey = process.env.AGENT_PRIVATE_KEY; // RSA private key in PEM format

// Initialize sender
const sender = new TACSender({
  domain: 'agent.example.com', // your agent domain (used as 'iss' in JWT)
  privateKey: agentPrivateKey
});

// Set data for a single recipient (merchant.com)
await sender.setRecipientsData({
  'merchant.com': {
    session: {
      consent: 'Buy Nike Air Jordan Retro shoes under $200',
      channel: 'CHAT'
    },
    user: {
      email: {
        address: 'john.doe@example.com',
        verifications: [
          {
            method: 'EMAIL_OTP',
            at: '2025-01-15T10:30:00Z'
          }
        ]
      }
    }
  }
});

// Generate TAC-Protocol message
const tacMessage = await sender.generateTACMessage();

// Make authenticated request to merchant
const response = await fetch('https://merchant.com/api/purchase', {
  method: 'POST',
  headers: {
    'TAC-Protocol': tacMessage
  }
});
```

### For Recipients (Merchants)

```javascript
import TACRecipient from './recipient.js';

// Get private key from env, vault or secret manager
const merchantPrivateKey = process.env.MERCHANT_PRIVATE_KEY; // RSA private key in PEM format

// Initialize recipient
const recipient = new TACRecipient({
  domain: 'merchant.com', // your domain as recipient
  privateKey: merchantPrivateKey
});

// Process TAC-Protocol message (from header or body)
const tacMessage = req.headers['TAC-Protocol'] || req.body.tacProtocol;
const result = await recipient.processTACMessage(tacMessage);

if (result.valid) {
  console.log('Request from:', result.issuer); // 'agent.example.com'

  if (result.data) {
    console.log('Data for me:', result.data);
    // Access decrypted data specific to this recipient
    console.log('User email:', result.data.user?.email?.address);
    console.log('Session consent:', result.data.session?.consent);
  }

  // Process the purchase...
} else {
  console.error('Authentication failed:', result.errors);
}
```

## Advanced Usage

### Using Password-Protected Private Keys

If your private key is encrypted with a password, you need to decrypt it before passing to the SDK:

```javascript
import crypto from 'node:crypto';
import fs from 'node:fs';
import { TACSender, TACRecipient } from 'trusted-agentic-commerce-protocol';

// Read encrypted PEM file
const encryptedPem = fs.readFileSync('encrypted-key.pem', 'utf8');
const password = process.env.KEY_PASSWORD;

// Decrypt the private key
const privateKey = crypto.createPrivateKey({
  key: encryptedPem,
  passphrase: password
});

// Use with TACSender
const sender = new TACSender({
  domain: 'agent.example.com',
  privateKey: privateKey  // Pass the decrypted KeyObject
});

// Use with TACRecipient
const recipient = new TACRecipient({
  domain: 'merchant.example.com',
  privateKey: privateKey  // Pass the decrypted KeyObject
});
```

### Collecting Vendor-Specific Data

Many security and fraud prevention vendors require specific tokens or identifiers to assess risk for the underlying user. Here's how to collect and pass vendor-specific data:

#### Example: Forter Integration

```javascript
// Step 1: Direct user to a web page that includes Forter's JavaScript SDK
// The page captures the Forter token client-side

// Step 2: On your server, collect the Forter token from cookies
// along with IP address and user agent from the request

const sender = new TACSender({
  domain: 'agent.example.com',
  privateKey: agentPrivateKey
});

await sender.setRecipientsData({
  'merchant.com': {
    user: {
      preferences: {
        brands: ['Nike', 'On', 'Asics'],
        sizes: {
          shoe: {
            value: 9,
            unit: 'US',
            method: 'HISTORICAL_PURCHASE',
            at: '2025-06-10T10:00:00Z'
          }
        }
      }
    }
  },
  'forter.com': {
    session: {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      forterToken: req.cookies.forterToken // captured from cookie
    }
  }
});

const tacMessage = await sender.generateTACMessage();
```

### Sending to Multiple Recipients

Use `addRecipientData` to incrementally add recipients with their specific data:

```javascript
const sender = new TACSender({
  domain: 'agent.example.com',
  privateKey: agentPrivateKey
});

// Add merchant with order details
await sender.addRecipientData('merchant.com', {
  order: {
    cart: [
      {
        sku: 'AJ1-RETRO-HIGH-BRD-9',
        name: 'Nike Air Jordan 1 Retro High',
        quantity: 1,
        price: 170.0
      },
      {
        sku: 'AJ-LACES-RED-54',
        name: 'Air Jordan Premium Replacement Laces - Red',
        quantity: 1,
        price: 15.0
      }
    ],
    shippingAddress: {
      name: 'Jane Doe',
      line1: '456 Main St',
      city: 'Springfield',
      region: 'IL',
      postal: '62704',
      country: 'US',
      type: 'RESIDENTIAL'
    }
  }
});

// Add fraud detection vendor with session data
await sender.addRecipientData('forter.com', {
  session: {
    forterToken: 'ftr_xyz'
  }
});

// Add payment processor with payment method
await sender.addRecipientData('stripe.com', {
  order: {
    paymentMethod: {
      type: 'CARD',
      card: {
        token: 'tok_xyz',
        brand: 'VISA',
        last4: 4242,
        expiryMonth: 12,
        expiryYear: 2026
      }
    }
  }
});

// Generate single message with all encrypted recipient data
const tacMessage = await sender.generateTACMessage();
```

### Setting Up Callbacks and Notifications

The TAC Protocol supports bidirectional notifications - agents can receive webhooks while users get SMS updates:

```javascript
const sender = new TACSender({
  domain: 'agent.example.com',
  privateKey: agentPrivateKey
});

await sender.setRecipientsData({
  'merchant.com': {
    user: {
      phone: {
        number: '+14155550123',
        type: 'MOBILE',
        verifications: [{
          method: 'SMS_OTP',
          at: '2025-07-30T18:20:00Z'
        }],
      },
      order: {
        cart: [{
          id: 'nike-123',
          name: 'Air Jordan 1',
          quantity: 1,
          price: 189.99
        }]
      },
    notifications: [
      // Webhook for the AI agent to receive updates
      {
        events: ['ORDER_STATUS', 'PAYMENT_STATUS'],
        type: 'URL',
        target: 'https://agent.example.com/webhooks'
      },
      // SMS notification for the end user
      {
        events: ['SHIPPING_STATUS'],
        type: 'SMS',
        target: '+14155551234' // User's phone number
      },
      // Slack notification for fraud team
      {
        events: ['DISPUTE_STATUS'],
        type: 'SLACK',
        target: 'https://hooks.slack.com/services/T00000000/B00000000/XXXX'
      }
    ]
  }
});

const tacMessage = await sender.generateTACMessage();
```

## Express.js Integration

```javascript
import express from 'express';
import TACRecipient from './recipient.js';

const app = express();
app.use(express.json());

// Get private key from env, vault or secret manager
const merchantPrivateKey = process.env.MERCHANT_PRIVATE_KEY;

// Initialize recipient
const recipient = new TACRecipient({
  domain: 'merchant.com',
  privateKey: merchantPrivateKey
});

// TAC protocol middleware
async function requireTACProtocol(req, res, next) {
  const tacMessage = req.get('TAC-Protocol') || req.body.tacProtocol;

  if (!tacMessage) {
    return res.status(401).json({
      error: 'Missing TAC-Protocol'
    });
  }

  const result = await recipient.processTACMessage(tacMessage);

  if (!result.valid) {
    return res.status(401).json({
      error: 'Invalid TAC-Protocol',
      details: result.errors
    });
  }

  req.tacProtocol = {
    issuer: result.issuer,
    expires: result.expires,
    data: result.data,
    recipients: result.recipients
  };
  next();
}

// Protected endpoint
app.post('/api/purchase', requireTACProtocol, (req, res) => {
  console.log(`Processing purchase from ${req.tacProtocol.issuer}`);
  if (req.tacProtocol.data) {
    // Process decrypted user data
    console.log('User email:', req.tacProtocol.data.user?.email?.address);
    console.log('Session consent:', req.tacProtocol.data.session?.consent);
  }
  res.json({ status: 'success', order_id: '12345' });
});

// JWKS endpoint for public key distribution
app.get('/.well-known/jwks.json', async (req, res) => {
  const jwk = await recipient.getPublicJWK();
  res.json({ keys: [jwk] });
});

app.listen(3000);
```

## Manual JWKS Management

```javascript
// Force refresh JWKS for a specific domain
const keys = await sender.fetchJWKS('merchant.com', true);

// Clear cache for specific domain or all
sender.clearCache('merchant.com');
sender.clearCache(); // Clear all

// Inspect TAC-Protocol message without decryption
const info = TACRecipient.inspect(tacMessage);
console.log('Recipients:', info.recipients); // ['merchant.com', 'forter.com']
console.log('Expires:', info.expires);
```

## Command Line Interface

The SDK includes CLI tools for testing and debugging TAC Protocol messages.

### Installation

```bash
npm install
npm link  # Optional: makes tacp-send and tacp-receive available globally
```

### tacp-send

Sign and encrypt TAC Protocol messages.

```bash
# Basic usage - message includes recipients as keys
node cli/tacp-send.js -k sender.pem -d sender.example.com \
  -m '{"merchant.com": {"user": {"email": "john@example.com"}}}'

# Multiple recipients
node cli/tacp-send.js -k sender.pem -d sender.example.com \
  -m '{"merchant.com": {"amount": 100}, "airline.com": {"flight": "AA123"}}'

# With password-protected key
node cli/tacp-send.js -k encrypted.pem -d sender.example.com -p "mypassword" \
  -m '{"merchant.com": {"order": "123"}}'

# From file
node cli/tacp-send.js -k sender.pem -d sender.example.com -i message.json

# From stdin
echo '{"merchant.com": {"amount": 100}}' | node cli/tacp-send.js -k sender.pem -d sender.example.com

# Raw output (base64 only, no JSON wrapper)
node cli/tacp-send.js -k sender.pem -d sender.example.com -m '{"merchant.com": {}}' --raw
```

**Options:**

| Option | Description |
|--------|-------------|
| `-k, --key <file>` | Sender's private key (PEM file) **[required]** |
| `-d, --domain <domain>` | Sender's domain (issuer) **[required]** |
| `-p, --password <password>` | Password for encrypted private key |
| `-m, --message <json>` | Message as JSON: `{"recipient.com": {...}, ...}` |
| `-i, --input <file>` | Input message file (default: stdin) |
| `-o, --output <file>` | Output file (default: stdout) |
| `--ttl <seconds>` | JWT TTL in seconds (default: 3600) |
| `--raw` | Output only base64 message |
| `-q, --quiet` | Suppress warnings |

**Message Format:**
```json
{
  "recipient1.com": { "data": "for recipient 1" },
  "recipient2.com": { "data": "for recipient 2" }
}
```

### tacp-receive

Decrypt and verify TAC Protocol messages.

```bash
# Basic usage
node cli/tacp-receive.js -k recipient.pem -d merchant.com -m "eyJ2ZXJzaW9uIjoiMj..."

# With password-protected key
node cli/tacp-receive.js -k encrypted.pem -d merchant.com -p "mypassword" -m "eyJ..."

# From file
node cli/tacp-receive.js -k recipient.pem -d merchant.com -i message.tac

# From stdin
echo "eyJ..." | node cli/tacp-receive.js -k recipient.pem -d merchant.com

# Raw output (payload only)
node cli/tacp-receive.js -k recipient.pem -d merchant.com -m "eyJ..." --raw

# Allow expired tokens (useful for testing/debugging)
node cli/tacp-receive.js -k recipient.pem -d merchant.com -m "eyJ..." --allow-expired
```

**Options:**

| Option | Description |
|--------|-------------|
| `-k, --key <file>` | Recipient's private key (PEM file) **[required]** |
| `-d, --domain <domain>` | Recipient's domain **[required]** |
| `-p, --password <password>` | Password for encrypted private key |
| `-m, --message <base64>` | TAC message as base64 string |
| `-i, --input <file>` | Input file (default: stdin) |
| `-o, --output <file>` | Output file (default: stdout) |
| `--raw` | Output only payload, no metadata |
| `--allow-expired` | Treat expired token as warning instead of error |
| `-v, --verbose` | Verbose output with warnings |
| `-q, --quiet` | Suppress warnings |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | File/IO error |
| 4 | Invalid key |
| 5 | Decryption failed |
| 6 | Signature verification failed |
| 7 | JWT expired/invalid |
| 8 | Network error (JWKS fetch) |

## Development

### Installation

```bash
npm install                 # Install dependencies
```

### Running Tests

The SDK includes a comprehensive test suite covering all aspects of the TAC Protocol implementation.

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:crypto         # Cryptographic operations
npm run test:cache          # JWKS cache management
npm run test:network        # Network operations & retries
npm run test:sender         # TACSender message creation
npm run test:recipient      # TACRecipient message processing
npm run test:errors         # Error handling & edge cases
npm run test:integration    # End-to-end scenarios
npm run test:utils          # Utility functions

# List available test suites
npm run test:list

# Watch mode (re-run on changes)
npm run test:watch
```

### Test Suites

| Suite | Description |
|-------|-------------|
| `crypto` | Key management, algorithm selection, and cryptographic primitives |
| `cache` | JWKS caching behavior, TTL expiration, concurrency, and race conditions |
| `network` | JWKS fetching, retry logic with exponential backoff, timeouts, and error handling |
| `sender` | TACSender message creation, multi-recipient encryption, JWT signing |
| `recipient` | TACRecipient message validation, signature verification, decryption |
| `errors` | Input validation, runtime errors, security edge cases, memory exhaustion |
| `integration` | Full end-to-end scenarios, performance tests, security validation |
| `utils` | Helper functions, key operations, base64 encoding, JWK conversion |

### Linting & Formatting

```bash
npm run lint                # Run ESLint
npm run lint:fix            # Auto-fix linting issues
npm run format              # Format with Prettier
npm run format:check        # Check formatting
npm run fix                 # Format + lint fix
```

## API Reference

### TACSender

#### Constructor Options

- `domain` (required) - Your agent's domain (used as JWT issuer)
- `privateKey` (required) - RSA private key for signing (KeyObject or PEM string)
- `ttl` - JWT validity in seconds (default: 3600)
- `cacheTimeout` - JWKS cache TTL in ms (default: 3600000)
- `maxRetries` - Max JWKS fetch retries (default: 3)
- `retryDelay` - Retry delay in ms (default: 1000)

#### Methods

- `setPrivateKey(privateKey)` - Set RSA private key (public key auto-derived)
- `generateKeyId()` - Get key ID for current private key
- `addRecipientData(domain, data)` - Add data for a specific recipient domain (async)
- `setRecipientsData(recipientsData)` - Set all recipients data (clears existing first, async)
- `clearRecipientData()` - Clear all pending recipient data
- `generateTACMessage()` - Create TAC-Protocol message with JWS+JWE encryption (async)
- `fetchJWKS(domain, forceRefresh?)` - Get recipient's public keys (async)
- `getPublicJWK()` - Get public key as JWK for JWKS endpoint (async)
- `clearCache(domain?)` - Clear JWKS cache for specific domain or all

### TACRecipient

#### Constructor Options

- `domain` (required) - Your domain (used to find your encrypted data)
- `privateKey` (required) - RSA private key for decryption (KeyObject or PEM string)
- `cacheTimeout` - JWKS cache TTL in ms (default: 3600000)
- `maxRetries` - Max JWKS fetch retries (default: 3)
- `retryDelay` - Retry delay in ms (default: 1000)

#### Methods

- `setPrivateKey(privateKey)` - Set RSA private key (public key auto-derived)
- `generateKeyId()` - Get key ID for current private key
- `processTACMessage(tacMessage)` - Process and decrypt TAC-Protocol message (async)
- `fetchJWKS(domain, forceRefresh?)` - Get sender's public keys (async)
- `getPublicJWK()` - Get public key as JWK for JWKS endpoint (async)
- `clearCache(domain?)` - Clear JWKS cache for specific domain or all

#### Static Methods

- `TACRecipient.inspect(tacMessage)` - Get message info without decryption

## Features

- **JWS+JWE Security**: JWT signatures (JWS) wrapped in JSON Web Encryption (JWE) for both authentication and confidentiality
- **RSA Key Support**: Compatible with RSA keys (minimum 2048-bit, 3072-bit recommended)
- **Multi-Recipient Encryption**: Single message encrypted for multiple recipients with data isolation
- **Key Rotation Support**: Automatic key ID (`kid`) handling for seamless key rotation
- **JWKS Integration**: Standard `.well-known/jwks.json` endpoint support
- **Network Resilience**: Exponential backoff retry with configurable timeouts
- **Intelligent Caching**: JWKS caching with TTL for performance optimization
- **Robust Error Handling**: Comprehensive error classes with specific error codes
- **Production Ready**: Full async/await support with TypeScript-style JSDoc annotations

## Requirements

- Node.js >= 18.0.0
- ES modules support
