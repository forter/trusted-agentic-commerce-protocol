# Trusted Agentic Commerce Protocol

A secure authentication and data encryption protocol for AI agents, merchants and merchant vendors. It combines:

- **JWT with digital signatures** for request authentication (RSA or EC)
- **JSON Web Encryption (JWE)** for sensitive data protection
- **JSON Web Key Sets (JWKS)** for key distribution

🎉 **[Read the full announcement on Forter Blog](https://www.forter.com/blog/proposing-a-trusted-agentic-commerce-protocol/)**

## Key Generation and Publishing

#### Option 1: RSA Keys (Default - Recommended for compatibility)

```bash
# Generate RSA key pair
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem

# Extract values for JWKS publishing:
# Extract modulus (n) - base64url encoded (single line output)
openssl rsa -in public.pem -pubin -modulus -noout | \
  cut -d'=' -f2 | xxd -r -p | base64 | tr -d '=\n' | tr '/+' '_-'

# Generate key ID (kid) - SHA-256 hash of public key
openssl rsa -in public.pem -pubin -outform DER 2>/dev/null | \
  openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '/+' '_-'
```

#### Option 2: Elliptic Curve Keys (Faster, smaller keys)

```bash
# Generate EC key pair (P-256 curve)
openssl ecparam -name prime256v1 -genkey -out private.pem
openssl ec -in private.pem -pubout -out public.pem

# Extract values for JWKS publishing:
# Extract x coordinate (base64url encoded)
openssl ec -in public.pem -pubin -text -noout 2>/dev/null | \
  grep -A 3 'pub:' | tail -3 | tr -d ' \n:' | xxd -r -p | \
  head -c 32 | base64 | tr -d '=' | tr '/+' '_-'

# Extract y coordinate (base64url encoded)
openssl ec -in public.pem -pubin -text -noout 2>/dev/null | \
  grep -A 3 'pub:' | tail -3 | tr -d ' \n:' | xxd -r -p | \
  tail -c 32 | base64 | tr -d '=' | tr '/+' '_-'

# Generate key ID (kid) - SHA-256 hash of public key
openssl ec -in public.pem -pubin -outform DER 2>/dev/null | \
  openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '/+' '_-'
```

### Publishing Keys

Publish your public keys at `https://your-domain.com/.well-known/jwks.json`:

**For RSA keys:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "<output from n extraction>",
      "e": "AQAB",
      "alg": "RS256",
      "kid": "<output from kid generation>"
    }
  ]
}
```

**For EC keys (P-256):**
```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "<output from x extraction>",
      "y": "<output from y extraction>",
      "alg": "ES256",
      "kid": "<output from kid generation>"
    }
  ]
}
```

## Protocol Participants

### Sender

Typically AI agent that makes requests on behalf of users. Sender:

- Signs JWTs to prove identity
- Encrypts sensitive user data for specific recipients
- Publishes public signing keys via JWKS

### Recipient

Typically merchant or merchant vendor that receives authenticated requests. Recipient:

- Verifies JWT signatures from senders
- Decrypts user data encrypted for them
- Publishes public encryption keys via JWKS

## Protocol Flow

1. **Sender prepares request**: Encrypts user data for specific recipients
2. **Sender signs JWT**: Creates signed JWT with issuer and expiration
3. **Sender encrypts JWT**: Encrypts signed JWT for multiple recipients using JWE
4. **Sender sends request**: Includes TAC-Protocol message in header or body
5. **Recipient decrypts**: Decrypts JWE to get signed JWT
6. **Recipient verifies**: Verifies JWT signature using sender's public key
7. **Recipient processes**: Handles authenticated request with decrypted data

## SDK Libraries

Ready-to-use SDK implementations:

- [JavaScript](sdk/javascript/) - Full implementation with examples
- [TypeScript](sdk/typescript/) - Full TypeScript implementation with type safety
- [Python](sdk/python/) - Full implementation with Flask/FastAPI examples
- PHP (coming soon)
- Java (coming soon)
- Go (coming soon)
- .NET (coming soon)

## Security Best Practices

1. **Key Management**
   - Store private keys securely
   - Rotate keys regularly
   - Never commit keys to version control

2. **HTTPS Only**
   - Always use HTTPS in production
   - Verify SSL certificates

3. **JWT Validation**
   - Check JWT expiry
   - Verify issuer claims
   - Validate signing algorithm

## License

MIT License