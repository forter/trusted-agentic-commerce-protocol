# Trusted Agentic Commerce Protocol SDK for TypeScript

TypeScript SDK implementing the Trusted Agentic Commerce Protocol for secure authentication and data encryption between AI agents, merchants and merchant vendors.

This SDK follows the [TAC Protocol Schema.](../../schema/)

## Features

- ✅ JWT-based authentication with RSA or EC signatures
- ✅ Multi-recipient JWE encryption using General JSON format
- ✅ JWKS key distribution at `/.well-known/jwks.json`
- ✅ Automatic key rotation support
- ✅ Request retry with exponential backoff
- ✅ JWKS caching with TTL
- ✅ Full TypeScript support with comprehensive types
- ✅ Schema-based types from TAC Protocol specification

## Quick Start

### For Senders (Typically AI Agents)

```typescript
import TACSender from './sender.js';

// Get private key from environment, vault or secret manager
const agentPrivateKey = process.env.AGENT_PRIVATE_KEY!; // RSA or EC private key in PEM format

// Initialize sender
const sender = new TACSender({
  domain: 'agent.example.com', // required (used as 'iss' in JWT)
  privateKey: agentPrivateKey, // required
  ttl: 3600, // JWT expiration in seconds (default: 3600)
  cacheTimeout: 3600000 // JWKS cache timeout in ms (default: 1 hour)
});

// Add data for specific recipients
sender.addRecipientData('merchant.com', {
  session: {
    consent: 'Buy Nike Air Jordan Retro shoes under $200'
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
});

sender.addRecipientData('forter.com', {
  session: {
    ipAddress: '192.168.1.1',
    userAgent: 'MyAgent/1.0',
    forterToken: 'ftr_xyz'
  }
});

// Or set all recipients at once
sender.setRecipientsData({
  'merchant.com': {
    session: {
      consent: 'Buy Nike Air Jordan Retro shoes under $200'
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
  },
  'forter.com': {
    session: {
      ipAddress: '192.168.1.1',
      userAgent: 'MyAgent/1.0',
      forterToken: 'ftr_xyz'
    }
  }
});

// Generate TAC-Protocol message with signed JWT and encrypted data
const tacMessage = await sender.generateTACMessage();

// Make the authenticated request (message can be used as header or in body)
const response = await fetch('https://merchant.com/api/purchase', {
  method: 'POST',
  headers: {
    'TAC-Protocol': tacMessage,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ /* your request payload */ })
});
```

### For Recipients (Typically Merchants or Merchant Vendors)

```typescript
import TACRecipient from './recipient.js';

// Get private key from environment, vault or secret manager
const merchantPrivateKey = process.env.MERCHANT_PRIVATE_KEY!; // RSA or EC private key in PEM format

// Initialize recipient
const recipient = new TACRecipient({
  domain: 'merchant.com', // required (your domain as recipient)
  privateKey: merchantPrivateKey, // required
  cacheTimeout: 3600000 // JWKS cache timeout in ms (default: 1 hour)
});

// Process TAC-Protocol message (from header or body)
const tacMessage = req.headers['TAC-protocol'] || req.body.tacProtocol;
const result = await recipient.processTACMessage(tacMessage);

if (result.valid) {
  console.log('Request from:', result.issuer);
  console.log('Token expires:', result.expires);
  
  if (result.data) {
    console.log('Data for me:', result.data);
    // Access decrypted data specific to this recipient
    console.log('User email:', result.data.user?.email?.address);
    console.log('Session consent:', result.data.session?.consent);
  }
  
  // You can also see which other recipients received data
  console.log('All recipients:', result.recipients);
} else {
  console.error('Authentication failed:', result.errors);
}
```

## Express.js Integration

```typescript
import express from 'express';
import TACRecipient from './recipient.js';

const app = express();
app.use(express.json());

// Get private key from environment, vault or secret manager
const merchantPrivateKey = process.env.MERCHANT_PRIVATE_KEY!;

// Initialize recipient
const recipient = new TACRecipient({
  domain: 'merchant.com',
  privateKey: merchantPrivateKey
});

// TAC authentication middleware
async function requireTACProtocol(req: express.Request, res: express.Response, next: express.NextFunction) {
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

  (req as any).tacProtocol = {
    issuer: result.issuer,
    expires: result.expires,
    data: result.data,
    recipients: result.recipients
  };
  next();
}

// Protected endpoint
app.post('/api/purchase', requireTACProtocol, (req: express.Request, res: express.Response) => {
  const tacProtocol = (req as any).tacProtocol;
  console.log(`Processing purchase from ${tacProtocol.issuer}`);
  if (tacProtocol.data) {
    // Process decrypted user data
    console.log('User email:', tacProtocol.data.user?.email?.address);
    console.log('Session consent:', tacProtocol.data.session?.consent);
  }
  res.json({ status: 'success', order_id: '12345' });
});

// JWKS endpoint for public key distribution
app.get('/.well-known/jwks.json', async (req: express.Request, res: express.Response) => {
  const jwk = await recipient.getPublicJWK();
  res.json({ keys: [jwk] });
});

app.listen(3000);
```

## Manual JWKS Management

```typescript
// Force refresh JWKS for a specific domain
const keys = await sender.fetchJWKS('merchant.com', true);

// Clear cache for specific domain or all
sender.clearCache('merchant.com');
sender.clearCache(); // Clear all

// Inspect TAC-Protocol message without decryption
const info = TACRecipient.inspect(tacMessage);
console.log('Recipients:', info.recipients); // ['merchant.com', 'forter.com']
console.log('Version:', info.version);
```

## TypeScript Schema Types

The SDK uses comprehensive TypeScript types from the official TAC Protocol schema. For static typing and reference, import from the protocol schema:

```typescript
import type { 
  User, 
  Order, 
  Session, 
  Email, 
  Phone, 
  PaymentMethod, 
  Address 
} from '../../schema/2025-08-21/schema.js';

const userData: User = {
  email: {
    address: 'user@example.com',
    verifications: [{
      method: 'EMAIL_OTP',
      at: '2025-01-15T10:30:00Z'
    }]
  },
  preferences: {
    brands: ['Nike', 'Adidas'],
    languages: ['en-US'],
    currencies: ['USD']
  }
};
```

## Building and Testing

```bash
# Install dependencies
npm install

# Build the TypeScript code
npm run build

# Run tests
npm test

# Watch mode for development
npm run dev
```

## API Reference

### TACSender

#### Constructor Options
- `domain` (required) - Your agent's domain (used as JWT issuer)
- `privateKey` (required) - RSA private key for signing (KeyObject or PEM string)
- `ttl` - JWT validity in seconds (default: 3600)
- `cacheTimeout` - JWKS cache TTL in ms (default: 3600000)
- `maxRetries` - Max JWKS fetch retries (default: 3)
- `retryDelay` - Initial retry delay in ms (default: 1000)

#### Methods
- `setPrivateKey(privateKey)` - Set RSA private key (public key auto-derived)
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
- `privateKey` (required) - RSA private key for decryption (KeyObject or PEM string)
- `cacheTimeout` - JWKS cache TTL in ms (default: 3600000)
- `maxRetries` - Max JWKS fetch retries (default: 3)
- `retryDelay` - Initial retry delay in ms (default: 1000)

#### Methods
- `setPrivateKey(privateKey)` - Set RSA private key (public key auto-derived)
- `generateKeyId()` - Get key ID for JWKS
- `processTACMessage(tacMessage)` - Process and decrypt TAC-Protocol message
- `fetchJWKS(domain, forceRefresh?)` - Get sender's public keys
- `clearCache(domain?)` - Clear JWKS cache
- `getPublicJWK()` - Get public key as JWK for JWKS endpoint (async)

#### Static Methods
- `TACRecipient.inspect(tacMessage)` - Get message info without decryption

## Requirements

- Node.js >= 18.0.0
- TypeScript >= 5.0.0
- ES modules support

## License

MIT License