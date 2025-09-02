#!/usr/bin/env node

/**
 * Comprehensive test runner for TAC Protocol TypeScript SDK
 *
 * This test runner executes all test suites with proper organization
 * and reporting, including performance metrics and coverage information.
 */

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ANSI colors for console output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

// Test suite configuration
const TEST_SUITES = [
  {
    name: "Cryptographic Operations",
    file: "crypto.test.js",
    description: "Key management, algorithm selection, and cryptographic primitives",
    timeout: 45000,
  },
  {
    name: "JWKS Cache Management",
    file: "cache.test.js",
    description: "Caching behavior, TTL, concurrency, and race conditions",
    timeout: 35000,
  },
  {
    name: "Network Operations",
    file: "network.test.js",
    description: "JWKS fetching, retries, timeouts, and error handling",
    timeout: 40000,
  },
  {
    name: "Message Generation (Sender)",
    file: "sender.test.js",
    description: "JWT signing, encryption, multi-recipient messaging",
    timeout: 35000,
  },
  {
    name: "Message Processing (Recipient)",
    file: "recipient.test.js",
    description: "JWT verification, decryption, signature validation",
    timeout: 35000,
  },
  {
    name: "Error Handling",
    file: "errors.test.js",
    description: "Error types, codes, and proper error propagation",
    timeout: 20000,
  },
  {
    name: "Integration Tests",
    file: "integration.test.js",
    description: "End-to-end workflows, cross-component interactions",
    timeout: 60000,
  },
  {
    name: "Utility Functions",
    file: "utils.test.js",
    description: "Helper functions, key operations, and data validation",
    timeout: 25000,
  },
];

function printBanner() {
  console.log(`${colors.cyan}${colors.bright}`);
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║                TAC Protocol TypeScript SDK                   ║");
  console.log("║                    Test Suite Runner                         ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log(`${colors.reset}\n`);
}

function printUsage() {
  console.log(`${colors.yellow}Usage:${colors.reset}`);
  console.log("  npm test                    - Run all test suites");
  console.log("  npm run test:crypto         - Run crypto tests only");
  console.log("  npm run test:cache          - Run cache tests only");
  console.log("  npm run test:network        - Run network tests only");
  console.log("  npm run test:sender         - Run sender tests only");
  console.log("  npm run test:recipient      - Run recipient tests only");
  console.log("  npm run test:errors         - Run error tests only");
  console.log("  npm run test:integration    - Run integration tests only");
  console.log("  npm run test:utils          - Run utils tests only");
  console.log("  npm run test:list           - List all available test suites");
  console.log("\n");
}

function listTestSuites() {
  console.log(`${colors.blue}${colors.bright}Available Test Suites:${colors.reset}\n`);

  TEST_SUITES.forEach((suite, index) => {
    console.log(`${colors.cyan}${index + 1}. ${suite.name}${colors.reset}`);
    console.log(`   File: ${suite.file}`);
    console.log(`   Description: ${suite.description}`);
    console.log(`   Timeout: ${suite.timeout}ms`);
    console.log("");
  });
}

function runNodeTest(testFile: string, timeout: number = 30000) {
  return new Promise<{ testFile: string; code: number; duration: number; stdout: string; stderr: string }>(
    (resolve) => {
      const startTime = Date.now();

      // Run built test file from dist directory
      const testPath = path.join(__dirname, testFile);

      console.log(`${colors.yellow}⏳ Running: ${testFile}${colors.reset}`);

      const child = spawn("node", ["--test", "--test-reporter=spec", testPath], {
        cwd: path.join(__dirname, ".."),
        stdio: ["inherit", "pipe", "pipe"],
        timeout,
      });

      let stdout = "";
      let stderr = "";

      child.stdout?.on("data", (data) => {
        const output = data.toString();
        stdout += output;
        // Show real-time output like the JavaScript version
        process.stdout.write(data);
      });

      child.stderr?.on("data", (data) => {
        const output = data.toString();
        stderr += output;
        process.stderr.write(data);
      });

      child.on("close", (code) => {
        const duration = Date.now() - startTime;

        const result = {
          testFile,
          code: code || 0,
          duration,
          stdout,
          stderr,
        };

        if (code === 0) {
          console.log(`${colors.green}✅ ${testFile} passed (${duration}ms)${colors.reset}`);
        } else {
          console.log(`${colors.red}❌ ${testFile} failed (${duration}ms)${colors.reset}`);
          if (stderr) {
            console.log(`${colors.red}Error output:${colors.reset}`);
            console.log(stderr);
          }
          if (stdout) {
            console.log(`${colors.yellow}Test output:${colors.reset}`);
            console.log(stdout);
          }
        }

        resolve(result);
      });

      child.on("error", (error) => {
        console.log(`${colors.red}❌ Error running ${testFile}: ${error.message}${colors.reset}`);
        resolve({
          testFile,
          code: 1,
          duration: Date.now() - startTime,
          stdout: "",
          stderr: error.message,
        });
      });
    }
  );
}

async function runTestSuite(suiteName: string) {
  const suite = TEST_SUITES.find(
    (s) => s.file.replace(".test.js", "") === suiteName || s.name.toLowerCase().includes(suiteName.toLowerCase())
  );

  if (!suite) {
    console.log(`${colors.red}❌ Test suite '${suiteName}' not found${colors.reset}`);
    console.log(
      `${colors.yellow}Available suites: ${TEST_SUITES.map((s) => s.file.replace(".test.js", "")).join(", ")}${colors.reset}`
    );
    return false;
  }

  console.log(`${colors.blue}${colors.bright}🧪 ${suite.name}${colors.reset}`);
  console.log(`${colors.cyan}${suite.description}${colors.reset}\n`);

  const result = await runNodeTest(suite.file, suite.timeout);

  console.log(""); // Add spacing
  return result.code === 0;
}

async function runAllTests() {
  console.log(`${colors.blue}${colors.bright}Running all test suites...${colors.reset}\n`);

  const results: Array<{ testFile: string; code: number; duration: number; stdout: string; stderr: string }> = [];
  let totalDuration = 0;

  for (const suite of TEST_SUITES) {
    console.log(`${colors.blue}${colors.bright}🧪 ${suite.name}${colors.reset}`);
    console.log(`${colors.cyan}${suite.description}${colors.reset}\n`);

    const result = await runNodeTest(suite.file, suite.timeout);
    results.push(result);
    totalDuration += result.duration;

    console.log(""); // Add spacing between tests
  }

  // Print summary
  const passed = results.filter((r) => r.code === 0).length;
  const failed = results.length - passed;

  console.log(`${colors.bright}═══════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bright}📊 Test Summary${colors.reset}`);
  console.log(`${colors.bright}═══════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`Total test suites: ${results.length}`);
  console.log(`${colors.green}✅ Passed: ${passed}${colors.reset}`);
  console.log(`${colors.red}❌ Failed: ${failed}${colors.reset}`);
  console.log(`Total duration: ${totalDuration}ms`);

  if (failed > 0) {
    console.log(`\n${colors.red}${colors.bright}Failed test suites:${colors.reset}`);
    results
      .filter((r) => r.code !== 0)
      .forEach((result) => {
        console.log(`${colors.red}  • ${result.testFile}${colors.reset}`);
      });
  }

  console.log(`${colors.bright}═══════════════════════════════════════════════════════════════${colors.reset}\n`);

  return failed === 0;
}

async function main() {
  printBanner();

  const args = process.argv.slice(2);

  if (args.length === 0) {
    const success = await runAllTests();
    process.exit(success ? 0 : 1);
  }

  const command = args[0]?.toLowerCase();

  switch (command) {
    case "list":
      listTestSuites();
      break;
    case "help":
    case "--help":
    case "-h":
      printUsage();
      break;
    default:
      if (command) {
        const success = await runTestSuite(command);
        process.exit(success ? 0 : 1);
      } else {
        printUsage();
        process.exit(1);
      }
  }
}

main().catch((error) => {
  console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
  process.exit(1);
});
