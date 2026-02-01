#!/usr/bin/env python3
"""
tacp-receive - Decrypt and verify TAC Protocol messages

Usage:
    tacp-receive -k private.pem -d merchant.example.com -m "eyJ..."
    tacp-receive -k private.pem -d merchant.example.com -p secret -i message.tac
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_INVALID_ARGS = 2
EXIT_FILE_ERROR = 3
EXIT_INVALID_KEY = 4
EXIT_DECRYPTION_FAILED = 5
EXIT_SIGNATURE_FAILED = 6
EXIT_JWT_INVALID = 7
EXIT_NETWORK_ERROR = 8


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tacp-receive",
        description="Decrypt and verify TAC Protocol messages",
    )
    parser.add_argument(
        "-k",
        "--key",
        required=True,
        help="Recipient's private key (PEM file)",
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Recipient's domain",
    )
    parser.add_argument(
        "-m",
        "--message",
        help="TAC message as base64 string",
    )
    parser.add_argument(
        "-i",
        "--input",
        help='Input file (default: stdin, use "-" for stdin)',
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output only payload, no metadata",
    )
    parser.add_argument(
        "--allow-expired",
        action="store_true",
        dest="allow_expired",
        help="Treat expired token as warning instead of error",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output with warnings",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress warnings",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.2.1",
    )
    return parser


async def main_async(args: argparse.Namespace) -> int:
    # Import here to avoid import errors when CLI module is loaded
    try:
        from recipient import TACRecipient
    except ImportError:
        # Handle direct script execution
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from recipient import TACRecipient

    # Read private key
    try:
        private_key_pem = Path(args.key).read_text()
    except Exception as e:
        if not args.quiet:
            print(f"Error: Cannot read key file: {args.key}", file=sys.stderr)
            print(str(e), file=sys.stderr)
        return EXIT_FILE_ERROR

    # Handle password-protected keys
    password = None
    # Try to load key without password first, prompt if encrypted
    try:
        from cryptography.hazmat.primitives import serialization

        serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except TypeError:
        # Key is encrypted, prompt for password
        import getpass

        try:
            password_str = getpass.getpass("Enter private key password: ")
            password = password_str.encode() if password_str else None
        except (EOFError, KeyboardInterrupt):
            print("\nError: Password input cancelled", file=sys.stderr)
            return EXIT_INVALID_KEY

    # Create TACRecipient
    try:
        recipient = TACRecipient(
            domain=args.domain,
            private_key=private_key_pem,
            password=password,
        )
    except Exception as e:
        if not args.quiet:
            print(f"Error: Invalid private key or wrong password: {e}", file=sys.stderr)
        return EXIT_INVALID_KEY

    # Read input: priority is --message > --input > stdin
    tac_message = ""
    if args.message:
        tac_message = args.message.strip()
    elif args.input and args.input != "-":
        try:
            tac_message = Path(args.input).read_text().strip()
        except Exception as e:
            if not args.quiet:
                print(f"Error: Cannot read input file: {e}", file=sys.stderr)
            return EXIT_FILE_ERROR
    else:
        # Read from stdin
        try:
            tac_message = sys.stdin.read().strip()
        except Exception as e:
            if not args.quiet:
                print(f"Error: Cannot read from stdin: {e}", file=sys.stderr)
            return EXIT_FILE_ERROR

    if not tac_message:
        if not args.quiet:
            print("Error: No input message provided", file=sys.stderr)
        return EXIT_INVALID_ARGS

    # Process the message
    result = await recipient.process_tac_message(tac_message)

    # Handle --allow-expired: move expiration errors to warnings
    errors = list(result.get("errors", []))
    warnings: list = []
    treat_as_valid = result.get("valid", False)

    if args.allow_expired and not result.get("valid"):
        expiration_errors = [
            e for e in errors if "exp" in e.lower() or "expired" in e.lower() or "timestamp check failed" in e.lower()
        ]
        other_errors = [
            e
            for e in errors
            if "exp" not in e.lower() and "expired" not in e.lower() and "timestamp check failed" not in e.lower()
        ]

        if expiration_errors and not other_errors:
            # Only expiration errors - treat as valid with warnings
            warnings.extend([f"[allowed] {e}" for e in expiration_errors])
            errors = []
            treat_as_valid = True
        elif expiration_errors:
            # Mixed errors - move expiration to warnings but still invalid
            warnings.extend([f"[allowed] {e}" for e in expiration_errors])
            errors = other_errors

    # Build output
    expires_iso = None
    if result.get("expires"):
        try:
            # Handle time.struct_time from Python SDK
            import time

            if isinstance(result["expires"], time.struct_time):
                expires_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", result["expires"])
            elif isinstance(result["expires"], datetime):
                expires_iso = result["expires"].isoformat()
            else:
                expires_iso = str(result["expires"])
        except Exception:
            expires_iso = str(result["expires"])

    output: Dict[str, Any] = {
        "success": treat_as_valid,
        "issuer": result.get("issuer"),
        "expires": expires_iso,
        "recipients": result.get("recipients", []),
        "payload": result.get("data"),
        "warnings": warnings,
        "errors": errors,
    }

    # Add expiration warnings for valid tokens
    if treat_as_valid and result.get("expires"):
        try:
            import time

            if isinstance(result["expires"], time.struct_time):
                expires_timestamp = time.mktime(result["expires"])
            else:
                expires_timestamp = result["expires"].timestamp()

            now = time.time()
            expires_in = int((expires_timestamp - now) / 60)
            if 0 < expires_in <= 5:
                output["warnings"].append(f"Token expires in {expires_in} minutes")
            elif expires_in <= 0 and not args.allow_expired:
                output["warnings"].append("Token has expired")
        except Exception:
            pass

    # Determine exit code based on errors
    exit_code = EXIT_SUCCESS
    if not treat_as_valid:
        error_str = " ".join(errors).lower()
        if "decryption failed" in error_str:
            exit_code = EXIT_DECRYPTION_FAILED
        elif "signature verification failed" in error_str:
            exit_code = EXIT_SIGNATURE_FAILED
        elif "expired" in error_str or "jwt" in error_str:
            exit_code = EXIT_JWT_INVALID
        elif "fetch" in error_str or "network" in error_str:
            exit_code = EXIT_NETWORK_ERROR
        else:
            exit_code = EXIT_GENERAL_ERROR

    # Output result
    if args.raw:
        output_str = json.dumps(result.get("data"), indent=2)
    else:
        output_str = json.dumps(output, indent=2)

    print(output_str)

    # Print warnings if verbose
    if args.verbose and output["warnings"]:
        print("Warnings:", file=sys.stderr)
        for warning in output["warnings"]:
            print(f"  - {warning}", file=sys.stderr)

    return exit_code


def main() -> None:
    parser = create_parser()
    args = parser.parse_args()

    try:
        exit_code = asyncio.run(main_async(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        sys.exit(EXIT_GENERAL_ERROR)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(EXIT_GENERAL_ERROR)


if __name__ == "__main__":
    main()
