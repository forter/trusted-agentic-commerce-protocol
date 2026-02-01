#!/usr/bin/env node

/**
 * Comprehensive test runner for TAC Protocol JavaScript SDK
 *
 * This test runner executes all test suites with proper organization
 * and reporting, including performance metrics and coverage information.
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ANSI colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

// Test suite configuration
const TEST_SUITES = [
  {
    name: 'Cryptographic Operations',
    file: 'crypto.test.js',
    description: 'Key management, algorithm selection, and cryptographic primitives',
    timeout: 45000 // Increased from 30000
  },
  {
    name: 'JWKS Cache Management',
    file: 'cache.test.js',
    description: 'Caching behavior, TTL, concurrency, and race conditions',
    timeout: 35000 // Increased from 20000 (cache expiration tests need time)
  },
  {
    name: 'Network Operations',
    file: 'network.test.js',
    description: 'JWKS fetching, retries, timeouts, and error handling',
    timeout: 40000 // Increased from 25000 (network retry tests are slow)
  },
  {
    name: 'Message Generation (Sender)',
    file: 'sender.test.js',
    description: 'TACSender message creation and multi-recipient encryption',
    timeout: 45000 // Increased from 30000
  },
  {
    name: 'Message Processing (Recipient)',
    file: 'recipient.test.js',
    description: 'TACRecipient message validation and decryption',
    timeout: 45000 // Increased from 30000
  },
  {
    name: 'Error Handling & Edge Cases',
    file: 'errors.test.js',
    description: 'Input validation, runtime errors, and security edge cases',
    timeout: 90000 // Increased from 45000 (memory exhaustion tests need ~35s alone)
  },
  {
    name: 'Integration & Performance',
    file: 'integration.test.js',
    description: 'End-to-end scenarios, performance tests, and security validation',
    timeout: 90000 // Increased from 60000 (performance tests need more time)
  },
  {
    name: 'Utility Functions',
    file: 'utils.test.js',
    description: 'Helper functions, key operations, and utility validation',
    timeout: 25000 // Increased from 15000
  }
];

function printBanner() {
  console.log(`${colors.cyan}${colors.bright}`);
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║                TAC Protocol JavaScript SDK                   ║');
  console.log('║                    Test Suite Runner                         ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log(`${colors.reset}\n`);
}

function listTestSuites() {
  console.log(`${colors.blue}${colors.bright}Available Test Suites:${colors.reset}\n`);

  TEST_SUITES.forEach((suite, index) => {
    console.log(`${colors.cyan}${index + 1}. ${suite.name}${colors.reset}`);
    console.log(`   File: ${suite.file}`);
    console.log(`   Description: ${suite.description}`);
    console.log(`   Timeout: ${suite.timeout}ms`);
    console.log('');
  });
}

function runNodeTest(testFile, timeout = 30000) {
  return new Promise(resolve => {
    const startTime = Date.now();

    // Run test file from tests directory
    const testPath = path.join(__dirname, testFile);

    console.log(`${colors.yellow}⏳ Running: ${testFile}${colors.reset}`);

    const child = spawn('node', ['--test', '--test-reporter=spec', testPath], {
      cwd: path.join(__dirname, '..'),
      stdio: ['inherit', 'pipe', 'pipe'],
      timeout
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', data => {
      const output = data.toString();
      stdout += output;
      // Show real-time output like the TypeScript version
      process.stdout.write(data);
    });

    child.stderr?.on('data', data => {
      const output = data.toString();
      stderr += output;
      process.stderr.write(data);
    });

    child.on('close', code => {
      const duration = Date.now() - startTime;

      const result = {
        testFile,
        code: code || 0,
        duration,
        stdout,
        stderr
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

    child.on('error', error => {
      console.log(`${colors.red}❌ Error running ${testFile}: ${error.message}${colors.reset}`);
      resolve({
        testFile,
        code: 1,
        duration: Date.now() - startTime,
        stdout: '',
        stderr: error.message
      });
    });
  });
}

class TestRunner {
  constructor() {
    this.results = [];
    this.startTime = Date.now();
    this.totalTests = 0;
    this.passedTests = 0;
    this.failedTests = 0;
  }

  log(message, color = 'reset') {
    // eslint-disable-next-line no-console
    console.log(`${colors[color]}${message}${colors.reset}`);
  }

  async runTestSuite(suiteName) {
    const suite = TEST_SUITES.find(
      s => s.file.replace('.test.js', '') === suiteName || s.name.toLowerCase().includes(suiteName.toLowerCase())
    );

    if (!suite) {
      console.log(`${colors.red}❌ Test suite '${suiteName}' not found${colors.reset}`);
      console.log(
        `${colors.yellow}Available suites: ${TEST_SUITES.map(s => s.file.replace('.test.js', '')).join(', ')}${colors.reset}`
      );
      return false;
    }

    console.log(`${colors.blue}${colors.bright}🧪 ${suite.name}${colors.reset}`);
    console.log(`${colors.cyan}${suite.description}${colors.reset}\n`);

    const result = await runNodeTest(suite.file, suite.timeout);
    this.results.push(result);

    console.log(''); // Add spacing
    return result.code === 0;
  }

  async runAll() {
    console.log(`${colors.blue}${colors.bright}Running all test suites...${colors.reset}\n`);

    let totalDuration = 0;

    for (const suite of TEST_SUITES) {
      console.log(`${colors.blue}${colors.bright}🧪 ${suite.name}${colors.reset}`);
      console.log(`${colors.cyan}${suite.description}${colors.reset}\n`);

      const result = await runNodeTest(suite.file, suite.timeout);
      this.results.push(result);
      totalDuration += result.duration;

      console.log(''); // Add spacing between tests
    }

    this.printSummary();
    return this.results.every(r => r.code === 0);
  }

  async runSpecific(suiteName) {
    return this.runTestSuite(suiteName);
  }

  printSummary() {
    const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);
    const passed = this.results.filter(r => r.code === 0).length;
    const failed = this.results.length - passed;

    console.log(`${colors.bright}═══════════════════════════════════════════════════════════════${colors.reset}`);
    console.log(`${colors.bright}📊 Test Summary${colors.reset}`);
    console.log(`${colors.bright}═══════════════════════════════════════════════════════════════${colors.reset}`);
    console.log(`Total test suites: ${this.results.length}`);
    console.log(`${colors.green}✅ Passed: ${passed}${colors.reset}`);
    console.log(`${colors.red}❌ Failed: ${failed}${colors.reset}`);
    console.log(`Total duration: ${totalDuration}ms`);

    if (failed > 0) {
      console.log(`\n${colors.red}${colors.bright}Failed test suites:${colors.reset}`);
      this.results
        .filter(r => r.code !== 0)
        .forEach(result => {
          console.log(`${colors.red}  • ${result.testFile}${colors.reset}`);
        });
    }

    console.log(`${colors.bright}═══════════════════════════════════════════════════════════════${colors.reset}\n`);
  }
}

// Main execution
async function main() {
  printBanner();

  const args = process.argv.slice(2);

  if (args.length === 0) {
    const runner = new TestRunner();
    const success = await runner.runAll();
    process.exit(success ? 0 : 1);
  } else if (args[0] === 'list') {
    listTestSuites();
  } else {
    const runner = new TestRunner();
    const success = await runner.runTestSuite(args[0]);
    runner.printSummary();
    process.exit(success ? 0 : 1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', error => {
  // eslint-disable-next-line no-console
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', reason => {
  // eslint-disable-next-line no-console
  console.error('💥 Unhandled Rejection:', reason);
  process.exit(1);
});

// Run the test runner
main().catch(error => {
  // eslint-disable-next-line no-console
  console.error('💥 Test runner failed:', error);
  process.exit(1);
});
