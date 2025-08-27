# Trusted Agentic Commerce Protocol JavaScript SDK

JavaScript SDK implementing the Trusted Agentic Commerce Protocol for secure authentication and data encryption between AI agents, merchants and merchant vendors.

This SDK follows the [Trusted Agentic Commerce Schema.](../../schema/)

## Getting Started
  - [Features](#features)
  - [Basic Usage](#basic-usage)
  - [Advanced Usage](#advanced-usage)
    - [Collecting Vendor-Specific Data](#collecting-vendor-specific-data)
    - [Sending to Multiple Recipients](#sending-to-multiple-recipients)
    - [Setting Up Callbacks and Notifications](#setting-up-callbacks-and-notifications)
  - [Express.js Integration](#expressjs-integration)
  - [Manual JWKS Management](#manual-jwks-management)
  - [Testing](#testing)
  - [API Reference](#api-reference)
  - [Requirements](#requirements)

## Features

- ✅ JWT-based authentication with RSA or EC signatures
- ✅ Multi-recipient JWE encryption using General JSON format
- ✅ JWKS key distribution at `/.well-known/jwks.json`
- ✅ Automatic key rotation support
- ✅ Request retry with exponential backoff
- ✅ JWKS caching with TTL
- ✅ Full TypeScript-compatible exports

## Basic Usage

### For Senders (AI Agents)

```javascript
import TACSender from './sender.js';

// Get private key from env, vault or secret manager
const agentPrivateKey = process.env.AGENT_PRIVATE_KEY; // RSA or EC private key in PEM format

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
    'TAC-Protocol': tacMessage,
  }
});
```

### For Recipients (Merchants)

```javascript
import TACRecipient from './recipient.js';

// Get private key from env, vault or secret manager
const merchantPrivateKey = process.env.MERCHANT_PRIVATE_KEY; // RSA or EC private key in PEM format

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
            value: 42,
            unit: 'EU',
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
        sku: 'AJ1-RETRO-HIGH-BRD-10.5',
        name: 'Nike Air Jordan 1 Retro High',
        quantity: 1,
        price: 170.00
      },
      {
        sku: 'AJ-LACES-RED-54',
        name: 'Air Jordan Premium Replacement Laces - Red',
        quantity: 1,
        price: 15.00
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
app.get('/.well-known/jwks.json', (req, res) => {
  const jwk = recipient.getPublicJWK();
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

## Testing

```bash
# Run tests
npm test

# Watch mode for development
npm run test:watch
```

## API Reference

### TACSender

#### Constructor Options
- `domain` (required) - Your agent's domain (used as JWT issuer)
- `privateKey` (required) - RSA or EC private key for signing (KeyObject or PEM string)
- `ttl` - JWT validity in seconds (default: 3600)
- `cacheTimeout` - JWKS cache TTL in ms (default: 3600000)
- `maxRetries` - Max JWKS fetch retries (default: 3)
- `retryDelay` - Initial retry delay in ms (default: 1000)

#### Methods
- `setPrivateKey(privateKey)` - Set RSA or EC private key (public key auto-derived)
- `generateKeyId()` - Get key ID for JWKS
- `addRecipientData(domain, data)` - Add and encrypt data for a recipient
- `generateTACMessage()` - Create TAC-Protocol message with JWT and encrypted data
- `setRecipientsData(recipientsData)` - Set all recipients data (clears existing first)
- `clearRecipientData()` - Clear all pending recipient data
- `fetchJWKS(domain, forceRefresh?)` - Get recipient's public keys
- `clearCache(domain?)` - Clear JWKS cache
- `getPublicJWK()` - Get public key as JWK for JWKS endpoint (async)

### TACRecipient

#### Constructor Options
- `domain` (required) - Your domain (used to find your encrypted data)
- `privateKey` (required) - RSA or EC private key for decryption (KeyObject or PEM string)
- `cacheTimeout` - JWKS cache TTL in ms (default: 3600000)
- `maxRetries` - Max JWKS fetch retries (default: 3)
- `retryDelay` - Initial retry delay in ms (default: 1000)

#### Methods
- `setPrivateKey(privateKey)` - Set RSA or EC private key (public key auto-derived)
- `generateKeyId()` - Get key ID for JWKS
- `processTACMessage(tacMessage)` - Process and decrypt TAC-Protocol message
- `fetchJWKS(domain, forceRefresh?)` - Get sender's public keys
- `clearCache(domain?)` - Clear JWKS cache
- `getPublicJWK()` - Get public key as JWK for JWKS endpoint (async)

#### Static Methods
- `TACRecipient.inspect(tacMessage)` - Get message info without decryption

## Requirements

- Node.js >= 18.0.0
- ES modules support