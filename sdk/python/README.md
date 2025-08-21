# Trusted Agentic Commerce Protocol SDK for Python

Python SDK implementing the Trusted Agentic Commerce Protocol for secure authentication and data encryption between AI agents, merchants and merchant vendors.

This SDK follows the [TAP Protocol Schema.](../../schema/)

## Features

- ✅ JWT-based authentication with RSA signatures
- ✅ Multi-recipient JWE encryption using General JSON format
- ✅ JWKS key distribution at `/.well-known/jwks.json`
- ✅ Automatic key rotation support
- ✅ Request retry with exponential backoff
- ✅ JWKS caching with TTL
- ✅ Full async/await support

## Quick Start

### For Senders (Typically AI Agents)

```python
import os
from trusted_agentic_commerce_protocol import TACSender

# Get private key from environment, vault or secret manager
agent_private_key = os.environ.get('AGENT_PRIVATE_KEY')  # RSA private key in PEM format

# Initialize sender
sender = TACSender(
    domain='agent.example.com', # required (used as 'iss' in JWT)
    private_key=agent_private_key, # required
    ttl=3600, # JWT expiration in seconds (default: 3600)
    cache_timeout=3600000 # JWKS cache timeout in ms (default: 1 hour)
)

# Add data for specific recipients
await sender.add_recipient_data('merchant.com', {
    'session': {
        'consent': 'Buy Nike Air Jordan Retro shoes under $200'
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
})

await sender.add_recipient_data('forter.com', {
    'session': {
        'ip_address': '192.168.1.1',
        'user_agent': 'MyAgent/1.0',
        'forter_token': 'ftr_xyz'
    }
})

# Or set all recipients at once
await sender.set_recipients_data({
    'merchant.com': {
        'session': {
            'consent': 'Buy Nike Air Jordan Retro shoes under $200'
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
    },
    'forter.com': {
        'session': {
            'ip_address': '192.168.1.1',
            'user_agent': 'MyAgent/1.0',
            'forter_token': 'ftr_xyz'
        }
    }
})

# Generate TAC-Protocol message with signed JWT and encrypted data
tac_message = await sender.generate_tac_message()

# Make the authenticated request (message can be used as header or in body)
import aiohttp
async with aiohttp.ClientSession() as session:
    async with session.post(
        'https://merchant.com/api/purchase',
        headers={
            'TAC-Protocol': tac_message,
            'Content-Type': 'application/json'
        },
        json={'product_id': 'nike_air_jordan'}
    ) as response:
        result = await response.json()
```

### For Recipients (Typically Merchants or Merchant Vendors)

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
    
    # You can also see which other recipients received data
    print(f"All recipients: {result['recipients']}")
else:
    print(f"Authentication failed: {result['errors']}")
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

## Testing

First, make sure dependencies are installed:
```bash
pip install --index-url https://pypi.org/simple/ "python-jose[cryptography]" aiohttp
```

Then run tests:
```bash
# Run tests with pytest (recommended for detailed output)
python -m pytest test.py -v

# Or using unittest directly
python test.py
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
- `generate_key_id()` - Get key ID for JWKS
- `add_recipient_data(domain, data)` - Add and encrypt data for a recipient
- `generate_tac_message()` - Create TAC-Protocol message with JWT and encrypted data
- `set_recipients_data(recipients_data)` - Set all recipients data (clears existing first)
- `clear_recipient_data()` - Clear all pending recipient data
- `fetch_jwks(domain, force_refresh=False)` - Get recipient's public keys
- `clear_cache(domain=None)` - Clear JWKS cache
- `get_public_jwk()` - Get public key as JWK for JWKS endpoint

### TACRecipient

#### Constructor Options
- `domain` (required) - Your domain (used to find your encrypted data)
- `private_key` (required) - RSA private key for decryption (KeyObject or PEM string)
- `cache_timeout` - JWKS cache TTL in ms (default: 3600000)
- `max_retries` - Max JWKS fetch retries (default: 3)
- `retry_delay` - Initial retry delay in ms (default: 1000)

#### Methods
- `set_private_key(private_key)` - Set RSA private key (public key auto-derived)
- `generate_key_id()` - Get key ID for JWKS
- `process_tac_message(tac_message)` - Process and decrypt TAC-Protocol message
- `fetch_jwks(domain, force_refresh=False)` - Get sender's public keys
- `clear_cache(domain=None)` - Clear JWKS cache
- `get_public_jwk()` - Get public key as JWK for JWKS endpoint

#### Static Methods
- `TACRecipient.inspect(tac_message)` - Get message info without decryption

## Requirements

- Python >= 3.8
- python-jose[cryptography] >= 3.3.0
- aiohttp >= 3.8.0

## License

MIT License