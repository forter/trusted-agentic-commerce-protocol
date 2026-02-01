# Changelog

All notable changes to the Trusted Agentic Commerce Protocol are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 - 2026-02-02

### Added
- CLI tools (`tacp-send`, `tacp-receive`) for all SDKs (JavaScript, TypeScript, Python)
- Password support for encrypted private keys (`-p, --password`)
- `--allow-expired` flag in `tacp-receive` to treat expired tokens as warnings
- End-to-end testing documentation in README files
- Comprehensive test suite documentation in README files

### Changed
- **Strict base64 encoding requirement**: Recipients now reject raw JSON input and require properly base64-encoded messages
  - Raw JSON (starting with `{` or `[`) returns: "must be base64-encoded (raw JSON not accepted)"
  - Invalid base64 format returns: "must be base64-encoded"
  - Valid base64 with invalid JSON returns: "Invalid TAC-Protocol message format"
- **JWT ID (`jti`) claim**: Already implemented - sender generates unique UUID, recipient extracts for replay detection
- **Configurable clock tolerance**: Already implemented - `clockTolerance` (JS/TS) or `clock_tolerance` (Python) constructor option

## 0.2.1 - 2025-10-27

### Fixed
- Python SDK: Fixed kwargs passing instead of dict (#3)
- Applied fix from PR #3 across SDKs

## 0.2.0 - 2025-09-03

### Added
- Comprehensive test suites for all SDKs (JavaScript, TypeScript, Python)
- Error codes and error handling classes
- JWKS cache expiry tests for Python SDK (#1)

### Changed
- Updated schema and examples

## 0.1.0 - 2025-08-21

### Added
- Initial release of the Trusted Agentic Commerce Protocol
- JavaScript SDK with TACSender and TACRecipient classes
- TypeScript SDK with full type definitions
- Python SDK with async/await support
- JWS+JWE security (JWT signatures wrapped in JSON Web Encryption)
- RSA and EC key support (P-256/384/521)
- Multi-recipient encryption with data isolation
- Key rotation support with automatic key ID handling
- JWKS integration (`.well-known/jwks.json` endpoint support)
- Network resilience with exponential backoff retry
- Intelligent JWKS caching with TTL
- Flask and FastAPI integration examples (Python)
- Express integration examples (JavaScript/TypeScript)

---

## Date Summary

| Date | Summary |
|------|---------|
| 2026-02-01 | Added CLI tools, security hardening (strict base64), comprehensive documentation |
| 2025-11-12 | Updated schema & examples |
| 2025-10-28 | Fixed kwargs passing in Python SDK (#3) |
| 2025-10-27 | Python SDK 0.2.1 release |
| 2025-09-03 | v0.2.0 release with tests & error codes for all SDKs |
| 2025-09-02 | Added Python JWKS cache expiry test (#1) |
| 2025-08-27-29 | README updates and documentation improvements |
| 2025-08-21 | Initial commit |
