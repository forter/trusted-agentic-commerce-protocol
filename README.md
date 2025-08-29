# Trusted Agentic Commerce Protocol

A secure authentication and data encryption protocol that allows AI agents, merchants and merchant vendors:

- ✅ Authenticate each other: verify the agent's identity and its relationship to the customer behind it
- ✅ Maintain rich customer data: reduce data losses and increase agents approval rate
- ✅ Improve user experience: create personalized, secure and frictionless checkout experience
- ✅ Prevent fraud: differentiates between legitimate agentic activity and fraud attempts

🎉 **[Read the announcement on Forter Blog](https://www.forter.com/blog/trusted-agentic-commerce-protocol/)**

## SDK Libraries

- [JavaScript](sdk/javascript/)
- [TypeScript](sdk/typescript/)
- [Python](sdk/python/)
- More coming soon

## Key Generation and Publishing

Trusted Agentic Commerce Protocol relies on:

- **JWT with digital signatures** for request authentication (RSA or EC)
- **JSON Web Encryption (JWE)** for sensitive data protection
- **JSON Web Key Sets (JWKS)** for key distribution

#### Option 1: Generate RSA Keys (Default - Recommended for compatibility)

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

#### Option 2: Generate Elliptic Curve Keys (Faster, smaller keys)

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

Typically AI agent:

- Makes requests on behalf of users
- Signs JWTs to prove identity
- Encrypts sensitive user data for specific recipients
- Publishes public signing keys via JWKS

### Recipient

Typically Merchant and/or Merchant Vendor:

- Receives authenticated requests
- Verifies JWT signatures from senders
- Decrypts user data encrypted for them
- Publishes public encryption keys via JWKS

## Protocol Flow

<p align="center">
  <a href="https://www.forter.com/wp-content/uploads/2025/08/forter-trusted-agentic-commerce-protocol.png" target="_blank">
    <img src="https://www.forter.com/wp-content/uploads/2025/08/forter-trusted-agentic-commerce-protocol.png" alt="Trusted Agentic Commerce Protocol Diagram" width="600"/>
  </a>
</p>

## Key Benefits

|         | **Without the protocol**                                                                                                                                         | **With the protocol**                                                                                                                                           |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Agent Developers**   | Your legitimate agent is blocked by aggressive merchant filters or fraudulent usage by other users, leading to failed tasks and frustrated users             | Your agent is recognized and trusted by merchant sites, leading to near-100% success rates for login and checkout and higher user satisfaction              |
| **Merchants**          | You block all bot traffic to protect your site because you’re unsure what is good or bad, losing out on potential sales and the potential of agentic commerce| You can distinguish between trusted agents and bot threats, enabling you to process more sales and offer personalized experiences based on verified user data|
| **Merchant vendors**   | You struggle to evaluate agent-driven transactions because you can’t distinguish legitimate agents from malicious bots, leading to missed revenue opportunities and strained merchant relationships | You receive verifiable identity and intent data from recognized agents, enabling precise risk assessments, fewer false declines, and stronger merchant trust in your services |
| **End-users**          | Your personal assistant fails to book a flight because it can’t complete a login, gets hit with a CAPTCHA or is blocked as "suspicious"                      | Your agent acts as a true extension of yourself, recognized and accepted by merchants, with your data and preferences respected                             |

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