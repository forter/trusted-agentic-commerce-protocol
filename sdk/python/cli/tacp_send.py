#!/usr/bin/env python3
"""
tacp-send - Sign and encrypt TAC Protocol messages

Usage:
    tacp-send -k private.pem -d agent.example.com -m '{"merchant.com": {"amount": 100}}'
    tacp-send -k private.pem -d agent.example.com -p secret -i message.json
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_INVALID_ARGS = 2
EXIT_FILE_ERROR = 3
EXIT_INVALID_KEY = 4
EXIT_NETWORK_ERROR = 8


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tacp-send",
        description="Sign and encrypt TAC Protocol messages",
    )
    parser.add_argument(
        "-k",
        "--key",
        required=True,
        help="Sender's private key (PEM file)",
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Sender's domain (issuer)",
    )
    parser.add_argument(
        "-m",
        "--message",
        help='Message as JSON: {"recipient.com": {...data...}, ...}',
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Input message file (default: stdin)",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=3600,
        help="JWT TTL in seconds (default: 3600)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output only base64 message",
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
        from sender import TACSender
    except ImportError:
        # Handle direct script execution
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from sender import TACSender

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

    # Validate TTL
    if args.ttl <= 0:
        print("Error: TTL must be a positive integer", file=sys.stderr)
        return EXIT_INVALID_ARGS

    # Create TACSender
    try:
        sender = TACSender(
            domain=args.domain,
            private_key=private_key_pem,
            ttl=args.ttl,
            password=password,
        )
    except Exception as e:
        if not args.quiet:
            print(f"Error: Invalid private key or wrong password: {e}", file=sys.stderr)
        return EXIT_INVALID_KEY

    # Read message (recipients with their data)
    message_data: Dict[str, Any] = {}

    # Priority: --message > --input > stdin
    if args.message:
        try:
            message_data = json.loads(args.message)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in --message: {e}", file=sys.stderr)
            return EXIT_INVALID_ARGS
    elif args.input and args.input != "-":
        try:
            input_content = Path(args.input).read_text().strip()
            message_data = json.loads(input_content) if input_content else {}
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in input file: {e}", file=sys.stderr)
            return EXIT_INVALID_ARGS
        except Exception as e:
            if not args.quiet:
                print(f"Error: Cannot read input file: {e}", file=sys.stderr)
            return EXIT_FILE_ERROR
    else:
        # Try stdin
        if not sys.stdin.isatty():
            try:
                stdin_data = sys.stdin.read().strip()
                if stdin_data:
                    message_data = json.loads(stdin_data)
                else:
                    print("Error: No message provided. Use -m or -i or pipe JSON to stdin.", file=sys.stderr)
                    print('Message format: {"recipient.com": {...data...}, ...}', file=sys.stderr)
                    return EXIT_INVALID_ARGS
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON from stdin: {e}", file=sys.stderr)
                return EXIT_INVALID_ARGS
        else:
            print("Error: No message provided. Use -m or -i or pipe JSON to stdin.", file=sys.stderr)
            print('Message format: {"recipient.com": {...data...}, ...}', file=sys.stderr)
            return EXIT_INVALID_ARGS

    # Validate message format
    if not isinstance(message_data, dict):
        print("Error: Message must be a JSON object with recipient domains as keys", file=sys.stderr)
        print('Example: {"merchant.com": {"amount": 100}, "airline.com": {"flight": "123"}}', file=sys.stderr)
        return EXIT_INVALID_ARGS

    recipients = list(message_data.keys())
    if len(recipients) == 0:
        print("Error: Message must contain at least one recipient", file=sys.stderr)
        return EXIT_INVALID_ARGS

    try:
        # Add recipient data
        for domain, data in message_data.items():
            await sender.add_recipient_data(domain, data)

        # Generate TAC message
        tac_message = await sender.generate_tac_message()

        if args.raw:
            print(tac_message)
        else:
            output: Dict[str, Any] = {
                "success": True,
                "issuer": args.domain,
                "recipients": recipients,
                "ttl": args.ttl,
                "message": tac_message,
            }
            print(json.dumps(output, indent=2))

        return EXIT_SUCCESS
    except Exception as e:
        if not args.quiet:
            print(f"Error: {e}", file=sys.stderr)
        error_str = str(e).lower()
        if "fetch" in error_str or "network" in error_str or "jwks" in error_str:
            return EXIT_NETWORK_ERROR
        return EXIT_GENERAL_ERROR


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
