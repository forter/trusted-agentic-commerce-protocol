#!/usr/bin/env node
import { program } from "commander";
import fs from "node:fs";
import crypto from "node:crypto";
import TACSender from "../src/sender.js";

// Exit codes
const EXIT_SUCCESS = 0;
const EXIT_GENERAL_ERROR = 1;
const EXIT_INVALID_ARGS = 2;
const EXIT_FILE_ERROR = 3;
const EXIT_INVALID_KEY = 4;
const EXIT_NETWORK_ERROR = 8;

interface CLIOptions {
  key: string;
  domain: string;
  message?: string;
  input?: string;
  ttl: string;
  raw?: boolean;
  quiet?: boolean;
}

interface CLIOutput {
  success: boolean;
  issuer: string;
  recipients: string[];
  ttl: number;
  message: string;
}

program
  .name("tacp-send")
  .description("Sign and encrypt TAC Protocol messages")
  .requiredOption("-k, --key <file>", "Sender's private key (PEM file)")
  .requiredOption("-d, --domain <domain>", "Sender's domain (issuer)")
  .option("-m, --message <json>", 'Message as JSON: {"recipient.com": {...data...}, ...}')
  .option("-i, --input <file>", "Input message file (default: stdin)")
  .option("--ttl <seconds>", "JWT TTL in seconds", "3600")
  .option("--raw", "Output only base64 message")
  .option("-q, --quiet", "Suppress warnings")
  .version("0.2.0");

program.parse();

const options = program.opts<CLIOptions>();

async function main(): Promise<void> {
  // Read private key
  let privateKeyPem: string;
  try {
    privateKeyPem = fs.readFileSync(options.key, "utf8");
  } catch (err) {
    if (!options.quiet) {
      console.error(`Error: Cannot read key file: ${options.key}`);
      console.error((err as Error).message);
    }
    process.exit(EXIT_FILE_ERROR);
  }

  // Handle password-protected keys
  let privateKey: crypto.KeyObject | string;
  try {
    // First try without password
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch (err) {
    // If it's an encrypted key, prompt for password
    if (
      (err as Error).message.includes("encrypted") ||
      (err as NodeJS.ErrnoException).code === "ERR_OSSL_UNSUPPORTED"
    ) {
      try {
        const password = await readPasswordFromStdin("Enter private key password: ");
        privateKey = crypto.createPrivateKey({
          key: privateKeyPem,
          passphrase: password,
        });
      } catch (pwErr) {
        if (!options.quiet) {
          console.error(`Error: Invalid private key or wrong password: ${(pwErr as Error).message}`);
        }
        process.exit(EXIT_INVALID_KEY);
      }
    } else {
      if (!options.quiet) {
        console.error(`Error: Invalid private key: ${(err as Error).message}`);
      }
      process.exit(EXIT_INVALID_KEY);
    }
  }

  // Parse TTL
  const ttl = parseInt(options.ttl, 10);
  if (isNaN(ttl) || ttl <= 0) {
    console.error("Error: TTL must be a positive integer");
    process.exit(EXIT_INVALID_ARGS);
  }

  // Create TACSender
  let sender: TACSender;
  try {
    sender = new TACSender({
      domain: options.domain,
      privateKey: privateKey,
      ttl: ttl,
    });
  } catch (err) {
    if (!options.quiet) {
      console.error(`Error: Invalid private key: ${(err as Error).message}`);
    }
    process.exit(EXIT_INVALID_KEY);
  }

  // Read message (recipients with their data)
  let messageData: Record<string, unknown>;

  // Priority: --message > --input > stdin
  if (options.message) {
    try {
      messageData = JSON.parse(options.message) as Record<string, unknown>;
    } catch (err) {
      console.error(`Error: Invalid JSON in --message: ${(err as Error).message}`);
      process.exit(EXIT_INVALID_ARGS);
    }
  } else if (options.input && options.input !== "-") {
    try {
      const inputContent = fs.readFileSync(options.input, "utf8").trim();
      messageData = inputContent ? (JSON.parse(inputContent) as Record<string, unknown>) : {};
    } catch (err) {
      if (!options.quiet) {
        console.error(`Error: Cannot read input file: ${(err as Error).message}`);
      }
      process.exit(EXIT_FILE_ERROR);
    }
  } else {
    // Try stdin (non-blocking for TTY)
    try {
      const stdinData = await readStdin();
      if (stdinData) {
        messageData = JSON.parse(stdinData) as Record<string, unknown>;
      } else {
        console.error("Error: No message provided. Use -m or -i or pipe JSON to stdin.");
        console.error('Message format: {"recipient.com": {...data...}, ...}');
        process.exit(EXIT_INVALID_ARGS);
      }
    } catch (err) {
      console.error(`Error: Invalid JSON from stdin: ${(err as Error).message}`);
      process.exit(EXIT_INVALID_ARGS);
    }
  }

  // Validate message format - should be object with recipient domains as keys
  if (typeof messageData !== "object" || messageData === null || Array.isArray(messageData)) {
    console.error("Error: Message must be a JSON object with recipient domains as keys");
    console.error('Example: {"merchant.com": {"amount": 100}, "airline.com": {"flight": "123"}}');
    process.exit(EXIT_INVALID_ARGS);
  }

  const recipients = Object.keys(messageData);
  if (recipients.length === 0) {
    console.error("Error: Message must contain at least one recipient");
    process.exit(EXIT_INVALID_ARGS);
  }

  try {
    // Add recipient data
    for (const [domain, data] of Object.entries(messageData)) {
      await sender.addRecipientData(domain, data as Record<string, unknown>);
    }

    // Generate TAC message
    const tacMessage = await sender.generateTACMessage();

    if (options.raw) {
      console.log(tacMessage);
    } else {
      const output: CLIOutput = {
        success: true,
        issuer: options.domain,
        recipients: recipients,
        ttl: ttl,
        message: tacMessage,
      };
      console.log(JSON.stringify(output, null, 2));
    }
    process.exit(EXIT_SUCCESS);
  } catch (err) {
    if (!options.quiet) {
      console.error(`Error: ${(err as Error).message}`);
    }
    const errorStr = (err as Error).message.toLowerCase();
    if (errorStr.includes("fetch") || errorStr.includes("network") || errorStr.includes("jwks")) {
      process.exit(EXIT_NETWORK_ERROR);
    }
    process.exit(EXIT_GENERAL_ERROR);
  }
}

function readPasswordFromStdin(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      // If not a TTY, read password from first line of stdin
      process.stdin.setEncoding("utf8");
      process.stdin.once("data", (chunk) => {
        const data = chunk.toString().split("\n")[0] || "";
        resolve(data);
      });
      process.stdin.once("error", reject);
      return;
    }

    // TTY mode - prompt for password
    process.stderr.write(prompt);

    const readline = require("readline");
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true,
    });

    // Disable echo for password input
    if (process.stdin.setRawMode) {
      process.stdin.setRawMode(true);
    }

    let password = "";
    const onData = (char: Buffer | string): void => {
      const charStr = char.toString();
      switch (charStr) {
        case "\n":
        case "\r":
        case "\u0004": // Ctrl+D
          if (process.stdin.setRawMode) {
            process.stdin.setRawMode(false);
          }
          process.stdin.removeListener("data", onData);
          process.stderr.write("\n");
          rl.close();
          resolve(password);
          break;
        case "\u0003": // Ctrl+C
          if (process.stdin.setRawMode) {
            process.stdin.setRawMode(false);
          }
          process.stderr.write("\n");
          rl.close();
          process.exit(1);
        case "\u007F": // Backspace
          password = password.slice(0, -1);
          break;
        default:
          password += charStr;
          break;
      }
    };
    process.stdin.on("data", onData);
  });
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";

    // If TTY with no pipe, resolve immediately with empty
    if (process.stdin.isTTY) {
      resolve("");
      return;
    }

    const timeout = setTimeout(() => {
      resolve(data.trim());
    }, 100);

    process.stdin.setEncoding("utf8");
    process.stdin.on("readable", () => {
      let chunk: string | null;
      while ((chunk = process.stdin.read() as string | null) !== null) {
        data += chunk;
      }
    });
    process.stdin.on("end", () => {
      clearTimeout(timeout);
      resolve(data.trim());
    });
    process.stdin.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(EXIT_GENERAL_ERROR);
});
