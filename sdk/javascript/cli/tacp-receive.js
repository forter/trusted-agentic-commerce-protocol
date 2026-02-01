#!/usr/bin/env node
import { program } from 'commander';
import fs from 'node:fs';
import crypto from 'node:crypto';
import TACRecipient from '../src/recipient.js';

// Exit codes
const EXIT_SUCCESS = 0;
const EXIT_GENERAL_ERROR = 1;
const EXIT_INVALID_ARGS = 2;
const EXIT_FILE_ERROR = 3;
const EXIT_INVALID_KEY = 4;
const EXIT_DECRYPTION_FAILED = 5;
const EXIT_SIGNATURE_FAILED = 6;
const EXIT_JWT_INVALID = 7;
const EXIT_NETWORK_ERROR = 8;

program
  .name('tacp-receive')
  .description('Decrypt and verify TAC Protocol messages')
  .requiredOption('-k, --key <file>', "Recipient's private key (PEM file)")
  .requiredOption('-d, --domain <domain>', "Recipient's domain")
  .option('-m, --message <base64>', 'TAC message as base64 string')
  .option('-i, --input <file>', 'Input file (default: stdin)')
  .option('--raw', 'Output only payload, no metadata')
  .option('--allow-expired', 'Treat expired token as warning instead of error')
  .option('-v, --verbose', 'Verbose output with warnings')
  .option('-q, --quiet', 'Suppress warnings')
  .version('0.2.0');

program.parse();

const options = program.opts();

async function main() {
  // Read private key
  let privateKeyPem;
  try {
    privateKeyPem = fs.readFileSync(options.key, 'utf8');
  } catch (err) {
    if (!options.quiet) {
      console.error(`Error: Cannot read key file: ${options.key}`);
      console.error(err.message);
    }
    process.exit(EXIT_FILE_ERROR);
  }

  // Handle password-protected keys
  let privateKey;
  try {
    // First try without password
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch (err) {
    // If it's an encrypted key, prompt for password
    if (err.message.includes('encrypted') || err.code === 'ERR_OSSL_UNSUPPORTED') {
      try {
        const password = await readPasswordFromStdin('Enter private key password: ');
        privateKey = crypto.createPrivateKey({
          key: privateKeyPem,
          passphrase: password
        });
      } catch (pwErr) {
        if (!options.quiet) {
          console.error(`Error: Invalid private key or wrong password: ${pwErr.message}`);
        }
        process.exit(EXIT_INVALID_KEY);
      }
    } else {
      if (!options.quiet) {
        console.error(`Error: Invalid private key: ${err.message}`);
      }
      process.exit(EXIT_INVALID_KEY);
    }
  }

  // Create TACRecipient
  let recipient;
  try {
    recipient = new TACRecipient({
      domain: options.domain,
      privateKey: privateKey
    });
  } catch (err) {
    if (!options.quiet) {
      console.error(`Error: Invalid private key: ${err.message}`);
    }
    process.exit(EXIT_INVALID_KEY);
  }

  // Read input: priority is --message > --input > stdin
  let tacMessage;
  if (options.message) {
    tacMessage = options.message.trim();
  } else if (options.input && options.input !== '-') {
    try {
      tacMessage = fs.readFileSync(options.input, 'utf8').trim();
    } catch (err) {
      if (!options.quiet) {
        console.error(`Error: Cannot read input file: ${err.message}`);
      }
      process.exit(EXIT_FILE_ERROR);
    }
  } else {
    // Read from stdin
    try {
      tacMessage = await readStdin();
    } catch (err) {
      if (!options.quiet) {
        console.error(`Error: Cannot read from stdin: ${err.message}`);
      }
      process.exit(EXIT_FILE_ERROR);
    }
  }

  if (!tacMessage) {
    if (!options.quiet) {
      console.error('Error: No input message provided');
    }
    process.exit(EXIT_INVALID_ARGS);
  }

  // Process the message
  const result = await recipient.processTACMessage(tacMessage);

  // Handle --allow-expired: move expiration errors to warnings
  let errors = [...result.errors];
  const warnings = [];
  let treatAsValid = result.valid;

  if (options.allowExpired && !result.valid) {
    const expirationErrors = errors.filter(
      e =>
        e.toLowerCase().includes('exp') ||
        e.toLowerCase().includes('expired') ||
        e.toLowerCase().includes('timestamp check failed')
    );
    const otherErrors = errors.filter(
      e =>
        !e.toLowerCase().includes('exp') &&
        !e.toLowerCase().includes('expired') &&
        !e.toLowerCase().includes('timestamp check failed')
    );

    if (expirationErrors.length > 0 && otherErrors.length === 0) {
      // Only expiration errors - treat as valid with warnings
      warnings.push(...expirationErrors.map(e => `[allowed] ${e}`));
      errors = [];
      treatAsValid = true;
    } else if (expirationErrors.length > 0) {
      // Mixed errors - move expiration to warnings but still invalid
      warnings.push(...expirationErrors.map(e => `[allowed] ${e}`));
      errors = otherErrors;
    }
  }

  // Build output
  const output = {
    success: treatAsValid,
    issuer: result.issuer,
    expires: result.expires ? result.expires.toISOString() : null,
    recipients: result.recipients,
    payload: result.data,
    warnings: warnings,
    errors: errors
  };

  // Add expiration warnings for valid tokens
  if (treatAsValid && result.expires) {
    const now = new Date();
    const expiresIn = Math.floor((result.expires - now) / 1000 / 60);
    if (expiresIn <= 5 && expiresIn > 0) {
      output.warnings.push(`Token expires in ${expiresIn} minutes`);
    } else if (expiresIn <= 0 && !options.allowExpired) {
      output.warnings.push('Token has expired');
    }
  }

  // Determine exit code based on errors
  let exitCode = EXIT_SUCCESS;
  if (!treatAsValid) {
    const errorStr = errors.join(' ').toLowerCase();
    if (errorStr.includes('decryption failed')) {
      exitCode = EXIT_DECRYPTION_FAILED;
    } else if (errorStr.includes('signature verification failed')) {
      exitCode = EXIT_SIGNATURE_FAILED;
    } else if (errorStr.includes('expired') || errorStr.includes('jwt')) {
      exitCode = EXIT_JWT_INVALID;
    } else if (errorStr.includes('fetch') || errorStr.includes('network')) {
      exitCode = EXIT_NETWORK_ERROR;
    } else {
      exitCode = EXIT_GENERAL_ERROR;
    }
  }

  // Output result
  let outputStr;
  if (options.raw) {
    outputStr = JSON.stringify(result.data, null, 2);
  } else {
    outputStr = JSON.stringify(output, null, 2);
  }

  console.log(outputStr);

  // Print warnings if verbose
  if (options.verbose && output.warnings.length > 0) {
    console.error('Warnings:');
    for (const warning of output.warnings) {
      console.error(`  - ${warning}`);
    }
  }

  process.exit(exitCode);
}

function readPasswordFromStdin(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      // If not a TTY, read password from first line of stdin
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.once('data', chunk => {
        data = chunk.toString().split('\n')[0];
        resolve(data);
      });
      process.stdin.once('error', reject);
      return;
    }

    // TTY mode - prompt for password
    process.stderr.write(prompt);

    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
      terminal: true
    });

    // Disable echo for password input
    if (process.stdin.setRawMode) {
      process.stdin.setRawMode(true);
    }

    let password = '';
    process.stdin.on('data', function onData(char) {
      char = char.toString();
      switch (char) {
        case '\n':
        case '\r':
        case '\u0004': // Ctrl+D
          if (process.stdin.setRawMode) {
            process.stdin.setRawMode(false);
          }
          process.stdin.removeListener('data', onData);
          process.stderr.write('\n');
          rl.close();
          resolve(password);
          break;
        case '\u0003': // Ctrl+C
          if (process.stdin.setRawMode) {
            process.stdin.setRawMode(false);
          }
          process.stderr.write('\n');
          rl.close();
          process.exit(1);
          break;
        case '\u007F': // Backspace
          password = password.slice(0, -1);
          break;
        default:
          password += char;
          break;
      }
    });
  });
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';

    // Set a short timeout for detecting interactive mode
    const timeout = setTimeout(() => {
      if (data === '' && process.stdin.isTTY) {
        reject(new Error('No input provided (stdin is a TTY)'));
      }
    }, 100);

    process.stdin.setEncoding('utf8');
    process.stdin.on('readable', () => {
      let chunk;
      while ((chunk = process.stdin.read()) !== null) {
        data += chunk;
      }
    });
    process.stdin.on('end', () => {
      clearTimeout(timeout);
      resolve(data.trim());
    });
    process.stdin.on('error', err => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(EXIT_GENERAL_ERROR);
});
