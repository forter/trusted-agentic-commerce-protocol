"""Protocol version for Trusted Agentic Commerce Protocol"""

PROTOCOL_VERSION = "2025-08-27"
SDK_VERSION = "0.1.0"
SDK_LANGUAGE = "Python"

def get_sender_user_agent() -> str:
    """Get User-Agent string for sender"""
    return f"TAC-Protocol/{PROTOCOL_VERSION} ({SDK_LANGUAGE}/{SDK_VERSION}; Sender)"

def get_recipient_user_agent() -> str:
    """Get User-Agent string for recipient"""
    return f"TAC-Protocol/{PROTOCOL_VERSION} ({SDK_LANGUAGE}/{SDK_VERSION}; Recipient)"
