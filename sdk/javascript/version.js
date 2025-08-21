// Protocol version for Trusted Agentic Commerce Protocol
export const PROTOCOL_VERSION = "2025-08-21";
export const SDK_VERSION = "0.1.0";
export const SDK_LANGUAGE = "JavaScript";

export function getSenderUserAgent() {
  return `TAC-Protocol/${PROTOCOL_VERSION} (${SDK_LANGUAGE}/${SDK_VERSION}; Sender)`;
}

export function getRecipientUserAgent() {
  return `TAC-Protocol/${PROTOCOL_VERSION} (${SDK_LANGUAGE}/${SDK_VERSION}; Recipient)`;
}
