# Trusted Agentic Commerce Protocol SDK for Python

Python SDK implementing the [Trusted Agentic Commerce Protocol,](https://www.forter.com/blog/proposing-a-trusted-agentic-commerce-protocol/) allowing merchants and agent developers to:

- ✅ Authenticate each other: verify the agent's identity and its relationship to the customer behind it
- ✅ Maintain rich customer data: reduce data losses experienced by merchants and increase agents approval rate
- ✅ Improve user experience: create personalized, secure and frictionless checkout experience
- ✅ Prevent fraud: differentiates between legitimate agentic activity and fraud attempts

## Getting Started
- [Trusted Agentic Commerce Protocol SDK for Python](#trusted-agentic-commerce-protocol-sdk-for-python)
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
  - [Flask Integration](#flask-integration)
  - [FastAPI Integration](#fastapi-integration)
  - [Manual JWKS Management](#manual-jwks-management)
  - [Development](#development)
    - [Installation](#installation)
    - [Running Tests](#running-tests)
    - [Test Suites](#test-suites)
    - [Linting, Formatting \& Type Checking](#linting-formatting--type-checking)
  - [CLI Tools](#cli-tools)
    - [Installation](#installation-1)
    - [tacp-send](#tacp-send)
    - [tacp-receive](#tacp-receive)
    - [Exit Codes](#exit-codes)
    - [Expected output](#expected-output)
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
  - [License](#license)

## Basic Usage

### For Senders (AI Agents)

```python
import os
from trusted_agentic_commerce_protocol import TACSender

# Get private key from environment, vault or secret manager
agent_private_key = os.environ.get('AGENT_PRIVATE_KEY')  # RSA private key in PEM format

# Initialize sender
sender = TACSender(
    domain='agent.example.com',  # your agent domain (used as 'iss' in JWT)
    private_key=agent_private_key
)

# Set data for a single recipient (merchant.com)
await sender.set_recipients_data({
    'merchant.com': {
        'session': {
            'consent': 'Buy Nike Air Jordan Retro shoes under $200',
            'channel': 'CHAT'
        },
        'user': {
            'email': {
                'address': 'john.doe@example.com',
                'verifications': [
                    {
                        'method': 'EMAIL_OTP',
                        'at': '2025-01-15T10:30:00Z'
                    }
                ]
            }
        }
    }
})

# Generate TAC-Protocol message
tac_message = await sender.generate_tac_message()

# Make authenticated request to merchant
import aiohttp
async with aiohttp.ClientSession() as session:
    async with session.post(
        'https://merchant.com/api/purchase',
        headers={'TAC-Protocol': tac_message}
    ) as response:
        result = await response.json()
```

### For Recipients (Merchants)

```python
import os
from trusted_agentic_commerce_protocol import TACRecipient

# Get private key from environment, vault or secret manager
merchant_private_key = os.environ.get('MERCHANT_PRIVATE_KEY')  # RSA private key in PEM format

# Initialize recipient
recipient = TACRecipient(
    domain='merchant.com', # required (your domain as recipient)
    private_key=merchant_private_key, # required
    cache_timeout=3600000 # JWKS cache timeout in ms (default: 1 hour)
)

# Process TAC-Protocol message (from header or body)
tac_message = request.headers.get('TAC-Protocol') or request.json.get('tacProtocol')
result = await recipient.process_tac_message(tac_message)

if result['valid']:
    print(f"Request from: {result['issuer']}")
    print(f"Token expires: {result['expires']}")
    
    if result['data']:
        print(f"Data for me: {result['data']}")
        # Access decrypted data specific to this recipient
        print(f"User email: {result['data']['user']['email']['address']}")
        print(f"Session consent: {result['data']['session']['consent']}")
    
    # Process the purchase...
else:
    print(f"Authentication failed: {result['errors']}")
```

## Advanced Usage

### Using Password-Protected Private Keys

The Python SDK has built-in support for password-protected private keys:

```python
import os
from trusted_agentic_commerce_protocol import TACSender, TACRecipient

# Read encrypted PEM file
with open('encrypted-key.pem', 'r') as f:
    encrypted_pem = f.read()

password = os.environ.get('KEY_PASSWORD').encode()  # Must be bytes

# Use with TACSender - pass password directly
sender = TACSender(
    domain='agent.example.com',
    private_key=encrypted_pem,
    password=password  # Built-in password support
)

# Use with TACRecipient - pass password directly
recipient = TACRecipient(
    domain='merchant.example.com',
    private_key=encrypted_pem,
    password=password  # Built-in password support
)

# You can also change keys later with set_private_key()
new_encrypted_key = open('new-key.pem').read()
new_password = b'new_password'
sender.set_private_key(new_encrypted_key, password=new_password)
```

### Collecting Vendor-Specific Data

Many security and fraud prevention vendors require specific tokens or identifiers. Here's how to collect and pass vendor-specific data:

#### Example: Forter Integration

```python
# Step 1: Direct user to a web page that includes Forter's JavaScript SDK
# The page captures the Forter token client-side

# Step 2: On your server, collect the Forter token from cookies
# along with IP address and user agent from the request

sender = TACSender(
    domain='agent.example.com',
    private_key=agent_private_key
)

await sender.set_recipients_data({
    'merchant.com': {
        'user': {
            'preferences': {
                'brands': ['Nike', 'On', 'Asics'],
                'sizes': {
                    'shoe': {
                        'value': 42,
                        'unit': 'EU',
                        'method': 'HISTORICAL_PURCHASE',
                        'at': '2025-06-10T10:00:00Z'
                    }
                }
            }
        }
    },
    'forter.com': {
        'session': {
            # Pass Forter-specific data
            'forterToken': request.cookies.get('forterToken'),  # captured from cookie
            'ipAddress': request.remote_addr,
            'userAgent': request.headers.get('User-Agent')
        }
    }
})

tac_message = await sender.generate_tac_message()
```

### Sending to Multiple Recipients

Use `add_recipient_data` to incrementally add recipients with their specific data:

```python
sender = TACSender(
    domain='agent.example.com',
    private_key=agent_private_key
)

# Add merchant with order details
await sender.add_recipient_data('merchant.com', {
    'order': {
        'cart': [
            {
                'sku': 'AJ1-RETRO-HIGH-BRD-10.5',
                'name': 'Nike Air Jordan 1 Retro High',
                'quantity': 1,
                'price': 170.00
            },
            {
                'sku': 'AJ-LACES-RED-54',
                'name': 'Air Jordan Premium Replacement Laces - Red',
                'quantity': 1,
                'price': 15.00
            }
        ],
        'shippingAddress': {
            'name': 'Jane Doe',
            'line1': '456 Main St',
            'city': 'Springfield',
            'region': 'IL',
            'postal': '62704',
            'country': 'US',
            'type': 'RESIDENTIAL'
        }
    }
})

# Add fraud detection vendor with session data
await sender.add_recipient_data('forter.com', {
    'session': {
        'forterToken': 'ftr_xyz'
    }
})

# Add payment processor with payment method
await sender.add_recipient_data('stripe.com', {
    'order': {
        'paymentMethod': {
            'type': 'CARD',
            'card': {
                'token': 'tok_visa_4242',
                'brand': 'VISA',
                'last4': 4242,
                'expiryMonth': 12,
                'expiryYear': 2026
            }
        }
    }
})

# Generate single message with all encrypted recipient data
tac_message = await sender.generate_tac_message()
```

### Setting Up Callbacks and Notifications

The TAC Protocol supports bidirectional notifications - agents can receive webhooks while users get SMS updates:

```python
sender = TACSender(
    domain='agent.example.com',
    private_key=agent_private_key
)

await sender.set_recipients_data({
    'merchant.com': {
        'user': {
            'phone': {
                'number': '+14155550123',
                'type': 'MOBILE',
                'verifications': [{
                    'method': 'SMS_OTP',
                    'at': '2025-07-30T18:20:00Z'
                }]
            }
        },
        'order': {
            'cart': [{
                'id': 'nike-123',
                'name': 'Air Jordan 1',
                'quantity': 1,
                'price': 189.99
            }]
        },
        # Bidirectional notifications
        'notifications': [
            # Webhook for the AI agent to receive updates
            {
                'events': ['ORDER_STATUS', 'PAYMENT_STATUS'],
                'type': 'URL',
                'target': 'https://agent.example.com/webhooks'
            },
            # SMS notification for the end user
            {
                'events': ['SHIPPING_STATUS'],
                'type': 'SMS',
                'target': '+14155551234'  # User's phone number
            },
            # Slack notification for fraud team
            {
                'events': ['DISPUTE_STATUS'],
                'type': 'SLACK',
                'target': 'https://hooks.slack.com/services/T00000000/B00000000/XXXX'
            }
        ]
    }
})

tac_message = await sender.generate_tac_message()
```

## Flask Integration

```python
from flask import Flask, request, jsonify
import asyncio
from trusted_agentic_commerce_protocol import TACRecipient

app = Flask(__name__)

# Get private key from environment, vault or secret manager
merchant_private_key = os.environ.get('MERCHANT_PRIVATE_KEY')

# Initialize recipient
recipient = TACRecipient(
    domain='merchant.com',
    private_key=merchant_private_key
)

def require_tac_protocol():
    """TAP authentication middleware"""
    tac_message = request.headers.get('TAC-Protocol') or request.json.get('tacProtocol')
    
    if not tac_message:
        return jsonify({'error': 'Missing TAC-Protocol message'}), 401

    # Use asyncio to run async function in sync Flask
    result = asyncio.run(recipient.process_tac_message(tac_message))

    if not result['valid']:
        return jsonify({
            'error': 'Invalid TAC-Protocol',
            'details': result['errors']
        }), 401

    return result

@app.route('/api/purchase', methods=['POST'])
def purchase():
    # Authenticate request
    tac_protocol = require_tac_protocol()
    if isinstance(tac_protocol, tuple):  # Error response
        return tac_protocol
    
    print(f"Processing purchase from {tac_protocol['issuer']}")
    if tac_protocol['data']:
        # Process decrypted user data
        print(f"User email: {tac_protocol['data']['user']['email']['address']}")
        print(f"Session consent: {tac_protocol['data']['session']['consent']}")
    
    return jsonify({'status': 'success', 'order_id': '12345'})

# JWKS endpoint for public key distribution
@app.route('/.well-known/jwks.json')
def jwks():
    jwk = recipient.get_public_jwk()
    return jsonify({'keys': [jwk]})

if __name__ == '__main__':
    app.run()
```

## FastAPI Integration

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from trusted_agentic_commerce_protocol import TACRecipient
import os

app = FastAPI()

# Get private key from environment, vault or secret manager
merchant_private_key = os.environ.get('MERCHANT_PRIVATE_KEY')

# Initialize recipient
recipient = TACRecipient(
    domain='merchant.com',
    private_key=merchant_private_key
)

async def require_tac_protocol(request: Request):
    """TAP authentication dependency"""
    tac_message = request.headers.get('TAC-Protocol')
    if not tac_message:
        # Try to get from JSON body
        try:
            body = await request.json()
            tac_message = body.get('tac_protocol')
        except:
            pass
    
    if not tac_message:
        raise HTTPException(
            status_code=401,
            detail={'error': 'Missing TAC-Protocol'}
        )
    
    result = await recipient.process_tac_message(tac_message)
    
    if not result['valid']:
        raise HTTPException(
            status_code=401,
            detail={
                'error': 'Invalid TAC-Protocol',
                'details': result['errors']
            }
        )
    
    return result

@app.post('/api/purchase')
async def purchase(tac_protocol = Depends(require_tac_protocol)):
    print(f"Processing purchase from {tac_protocol['issuer']}")
    if tac_protocol['data']:
        # Process decrypted user data
        print(f"User email: {tac_protocol['data']['user']['email']['address']}")
        print(f"Session consent: {tac_protocol['data']['session']['consent']}")
    
    return {'status': 'success', 'order_id': '12345'}

# JWKS endpoint for public key distribution
@app.get('/.well-known/jwks.json')
async def jwks():
    jwk = recipient.get_public_jwk()
    return {'keys': [jwk]}
```

## Manual JWKS Management

```python
# Force refresh JWKS for a specific domain
keys = await sender.fetch_jwks('merchant.com', force_refresh=True)

# Clear cache for specific domain or all
sender.clear_cache('merchant.com')
sender.clear_cache()  # Clear all

# Inspect TAC-Protocol message without decryption
info = TACRecipient.inspect(tac_message)
print(f"Recipients: {info['recipients']}")  # ['merchant.com', 'forter.com']
print(f"Version: {info['version']}")
```

## Development

### Installation

```bash
make install-dev           # Install development dependencies
# Or manually:
pip install -r requirements-dev.txt
```

### Running Tests

The SDK includes a comprehensive test suite covering all aspects of the TAC Protocol implementation. Tests use pytest with asyncio support.

```bash
# Run all tests
make test

# Run specific test suite
make test-crypto           # Cryptographic operations
make test-cache            # JWKS cache management
make test-network          # Network operations & retries
make test-sender           # TACSender message creation
make test-recipient        # TACRecipient message processing
make test-errors           # Error handling & edge cases
make test-integration      # End-to-end scenarios
make test-utils            # Utility functions

# List available test modules
make test-list

# Or run directly with pytest
pytest tests/                          # All tests
pytest tests/test_sender.py            # Specific file
pytest tests/test_sender.py -k "test_" # Specific pattern
pytest tests/ -v                       # Verbose output
pytest tests/ --cov=src                # With coverage
```

### Test Suites

| Suite | Description |
|-------|-------------|
| `crypto` | Key management, algorithm selection, and cryptographic primitives |
| `cache` | JWKS caching behavior, TTL expiration, concurrency, and race conditions |
| `network` | JWKS fetching, retry logic with exponential backoff, timeouts, and error handling |
| `sender` | TACSender message creation, multi-recipient encryption, JWT signing |
| `recipient` | TACRecipient message validation, signature verification, decryption |
| `errors` | Input validation, runtime errors, security edge cases |
| `integration` | Full end-to-end scenarios, performance tests, security validation |
| `utils` | Helper functions, key operations, base64 encoding, JWK conversion |

### Linting, Formatting & Type Checking

```bash
make lint                  # Run flake8 linting
make lint-fix              # Auto-fix then show remaining issues
make format                # Format with Black + isort
make format-check          # Check formatting without changes
make type-check            # Run mypy type checking
make fix                   # Format + lint fix
make clean                 # Clean generated files
make dev                   # Full workflow: clean, format, lint, type-check, test
```

## CLI Tools

The SDK includes command-line tools for testing and debugging TAC Protocol messages.

### Installation

After installing the SDK, the CLI tools are available as:
- `tacp-send` - Sign and encrypt TAC messages
- `tacp-receive` - Decrypt and verify TAC messages

### tacp-send

Sign and encrypt TAC Protocol messages.

```bash
# Basic usage with message as argument
tacp-send -k sender.pem -d agent.example.com -m '{"merchant.com": {"user": {"id": "123"}}}'

# With password-protected key
tacp-send -k sender.pem -d agent.example.com -p mypassword -m '{"merchant.com": {"data": "value"}}'

# From file input
tacp-send -k sender.pem -d agent.example.com -i payload.json

# From stdin
echo '{"merchant.com": {"user": {"id": "123"}}}' | tacp-send -k sender.pem -d agent.example.com

# Custom TTL
tacp-send -k sender.pem -d agent.example.com --ttl 7200 -m '{"merchant.com": {}}'

# Output to file
tacp-send -k sender.pem -d agent.example.com -m '{"merchant.com": {}}' -o message.tac
```

**Options:**
| Option | Description |
|--------|-------------|
| `-k, --key <file>` | Sender's private key (PEM file) **[required]** |
| `-d, --domain <domain>` | Sender's domain (issuer) **[required]** |
| `-p, --password <password>` | Password for encrypted private key |
| `-m, --message <json>` | Message as JSON: `{"recipient.com": {...data...}, ...}` |
| `-i, --input <file>` | Input message file (default: stdin) |
| `-o, --output <file>` | Output file (default: stdout) |
| `--ttl <seconds>` | JWT TTL in seconds (default: 3600) |
| `--raw` | Output only base64 message |
| `-q, --quiet` | Suppress warnings |

### tacp-receive

Decrypt and verify TAC Protocol messages.

```bash
# Basic usage with message as argument
tacp-receive -k recipient.pem -d merchant.com -m "eyJ..."

# With password-protected key
tacp-receive -k recipient.pem -d merchant.com -p mypassword -m "eyJ..."

# From file input
tacp-receive -k recipient.pem -d merchant.com -i message.tac

# From stdin
echo "eyJ..." | tacp-receive -k recipient.pem -d merchant.com

# Allow expired tokens (for testing)
tacp-receive -k recipient.pem -d merchant.com --allow-expired -m "eyJ..."

# Raw output (payload only)
tacp-receive -k recipient.pem -d merchant.com --raw -m "eyJ..."

# Verbose output with warnings
tacp-receive -k recipient.pem -d merchant.com -v -m "eyJ..."
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

### Expected output

```json
{
  "success": true,
  "issuer": "sender.example.com",
  "expires": "2026-02-01T15:30:00.000Z",
  "recipients": ["recipient.example.com"],
  "payload": {
    "user": {
      "id": "user123",
      "email": "test@example.com"
    }
  },
  "warnings": [],
  "errors": []
}
```

## API Reference

### TACSender

#### Constructor Options
- `domain` (required) - Your agent's domain (used as JWT issuer)
- `private_key` (required) - RSA private key for signing (KeyObject or PEM string)
- `ttl` - JWT validity in seconds (default: 3600)
- `cache_timeout` - JWKS cache TTL in ms (default: 3600000)
- `max_retries` - Max JWKS fetch retries (default: 3)
- `retry_delay` - Initial retry delay in ms (default: 1000)

#### Methods

- `set_private_key(private_key)` - Set RSA private key (public key auto-derived)
- `generate_key_id()` - Get key ID for current private key
- `add_recipient_data(domain, data)` - Add data for a specific recipient domain (async)
- `set_recipients_data(recipients_data)` - Set all recipients data (clears existing first, async)
- `clear_recipient_data()` - Clear all pending recipient data
- `generate_tac_message()` - Create TAC-Protocol message with JWS+JWE encryption (async)
- `fetch_jwks(domain, force_refresh=False)` - Get recipient's public keys (async)
- `get_public_jwk()` - Get public key as JWK for JWKS endpoint (async)
- `clear_cache(domain=None)` - Clear JWKS cache for specific domain or all

### TACRecipient

#### Constructor Options
- `domain` (required) - Your domain (used to find your encrypted data)
- `private_key` (required) - RSA private key for decryption (KeyObject or PEM string)
- `cache_timeout` - JWKS cache TTL in ms (default: 3600000)
- `max_retries` - Max JWKS fetch retries (default: 3)
- `retry_delay` - Initial retry delay in ms (default: 1000)

#### Methods

- `set_private_key(private_key)` - Set RSA private key (public key auto-derived)
- `generate_key_id()` - Get key ID for current private key
- `process_tac_message(tac_message)` - Process and decrypt TAC-Protocol message (async)
- `fetch_jwks(domain, force_refresh=False)` - Get sender's public keys (async)
- `get_public_jwk()` - Get public key as JWK for JWKS endpoint (async)
- `clear_cache(domain=None)` - Clear JWKS cache for specific domain or all

#### Static Methods
- `TACRecipient.inspect(tac_message)` - Get message info without decryption

## Features

- **JWS+JWE Security**: JWT signatures (JWS) wrapped in JSON Web Encryption (JWE) for both authentication and confidentiality
- **RSA Key Support**: Compatible with RSA keys (minimum 2048-bit, 3072-bit recommended)
- **Multi-Recipient Encryption**: Single message encrypted for multiple recipients with data isolation
- **Key Rotation Support**: Automatic key ID (`kid`) handling for seamless key rotation
- **JWKS Integration**: Standard `.well-known/jwks.json` endpoint support
- **Network Resilience**: Exponential backoff retry with configurable timeouts
- **Intelligent Caching**: JWKS caching with TTL for performance optimization
- **Robust Error Handling**: Comprehensive error classes with specific error codes
- **Production Ready**: Full async/await support with comprehensive test coverage

## Requirements

- Python >= 3.8
- python-jose[cryptography] >= 3.3.0
- aiohttp >= 3.8.0

## License

MIT License