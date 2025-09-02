#!/usr/bin/env python3
"""
Comprehensive test runner for TAC Protocol Python SDK

This test runner executes all test suites with proper organization
and reporting, including performance metrics and coverage information.
"""

import argparse
import os
import subprocess
import sys
import time
from typing import List


class Colors:
    """ANSI color codes for console output"""

    RESET = "\033[0m"
    BRIGHT = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


class TestSuite:
    """Test suite configuration"""

    def __init__(self, name: str, file: str, description: str, timeout: int = 60):
        self.name = name
        self.file = file
        self.description = description
        self.timeout = timeout


# Test suite configuration
TEST_SUITES = [
    TestSuite(
        name="Cryptographic Operations",
        file="test_crypto.py",
        description="Key management, algorithm selection, and cryptographic primitives",
        timeout=45,
    ),
    TestSuite(
        name="JWKS Cache Management",
        file="test_cache.py",
        description="Caching behavior, TTL, concurrency, and race conditions",
        timeout=35,
    ),
    TestSuite(
        name="Network Operations",
        file="test_network.py",
        description="JWKS fetching, retries, timeouts, and error handling",
        timeout=40,
    ),
    TestSuite(
        name="Message Generation (Sender)",
        file="test_sender.py",
        description="JWT signing, encryption, multi-recipient messaging",
        timeout=35,
    ),
    TestSuite(
        name="Message Processing (Recipient)",
        file="test_recipient.py",
        description="JWT verification, decryption, signature validation",
        timeout=35,
    ),
    TestSuite(
        name="Error Handling",
        file="test_errors.py",
        description="Error types, codes, and proper error propagation",
        timeout=20,
    ),
    TestSuite(
        name="Integration Tests",
        file="test_integration.py",
        description="End-to-end workflows, cross-component interactions",
        timeout=60,
    ),
    TestSuite(
        name="Utility Functions",
        file="test_utils.py",
        description="Helper functions, key operations, and data validation",
        timeout=25,
    ),
]


class TestResult:
    """Test result container"""

    def __init__(self, suite: TestSuite, success: bool, duration: float, output: str = "", error: str = ""):
        self.suite = suite
        self.success = success
        self.duration = duration
        self.output = output
        self.error = error


class TestRunner:
    """Main test runner class"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.start_time = time.time()

    def print_banner(self):
        """Print the test runner banner"""
        print(f"{Colors.CYAN}{Colors.BRIGHT}")
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                TAC Protocol Python SDK                       ║")
        print("║                    Test Suite Runner                         ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}\n")

    def print_usage(self):
        """Print usage information"""
        print(f"{Colors.YELLOW}Usage:{Colors.RESET}")
        print("  python test_runner.py                    - Run all test suites")
        print("  python test_runner.py crypto             - Run crypto tests only")
        print("  python test_runner.py cache              - Run cache tests only")
        print("  python test_runner.py network            - Run network tests only")
        print("  python test_runner.py sender             - Run sender tests only")
        print("  python test_runner.py recipient          - Run recipient tests only")
        print("  python test_runner.py errors             - Run error tests only")
        print("  python test_runner.py integration        - Run integration tests only")
        print("  python test_runner.py utils              - Run utils tests only")
        print("  python test_runner.py list               - List all available test suites")
        print("\n")

    def list_test_suites(self):
        """List all available test suites"""
        print(f"{Colors.BLUE}{Colors.BRIGHT}Available Test Suites:{Colors.RESET}\n")

        for i, suite in enumerate(TEST_SUITES, 1):
            print(f"{Colors.CYAN}{i}. {suite.name}{Colors.RESET}")
            print(f"   File: {suite.file}")
            print(f"   Description: {suite.description}")
            print(f"   Timeout: {suite.timeout}s")
            print("")

    def run_test_suite(self, suite: TestSuite) -> TestResult:
        """Run a single test suite"""
        print(f"{Colors.BLUE}{Colors.BRIGHT}🧪 {suite.name}{Colors.RESET}")
        print(f"{Colors.CYAN}{suite.description}{Colors.RESET}\n")

        test_file = os.path.join(os.path.dirname(__file__), suite.file)

        if not os.path.exists(test_file):
            print(f"{Colors.RED}❌ Test file {suite.file} not found{Colors.RESET}")
            return TestResult(suite, False, 0, "", f"Test file {suite.file} not found")

        print(f"{Colors.YELLOW}⏳ Running: {suite.file}{Colors.RESET}")

        start_time = time.time()

        try:
            # Run the test with unittest discovery showing real-time output
            process = subprocess.Popen(
                [sys.executable, "-m", "unittest", "-v", suite.file.replace(".py", "")],
                cwd=os.path.dirname(__file__),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            stdout_lines = []
            stderr_lines = []

            # Show real-time output
            while True:
                output = process.stdout.readline()
                if output == "" and process.poll() is not None:
                    break
                if output:
                    print(output.strip())
                    stdout_lines.append(output)

            # Wait for process to complete
            return_code = process.wait()
            duration = time.time() - start_time

            stdout_text = "".join(stdout_lines)
            stderr_text = "".join(stderr_lines)

            if return_code == 0:
                print(f"{Colors.GREEN}✅ {suite.file} passed ({duration:.0f}ms){Colors.RESET}")
                return TestResult(suite, True, duration, stdout_text, stderr_text)
            else:
                print(f"{Colors.RED}❌ {suite.file} failed ({duration:.0f}ms){Colors.RESET}")
                # Don't re-print output since we already showed it in real-time
                return TestResult(suite, False, duration, stdout_text, stderr_text)

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            print(f"{Colors.RED}❌ {suite.file} timed out after {suite.timeout}s{Colors.RESET}")
            return TestResult(suite, False, duration, "", f"Test timed out after {suite.timeout}s")

        except Exception as e:
            duration = time.time() - start_time
            print(f"{Colors.RED}❌ Error running {suite.file}: {str(e)}{Colors.RESET}")
            return TestResult(suite, False, duration, "", str(e))

    def run_single_suite(self, suite_name: str) -> bool:
        """Run a specific test suite by name"""
        suite = None
        for s in TEST_SUITES:
            if (
                s.file.replace(".py", "").replace("test_", "") == suite_name.lower()
                or suite_name.lower() in s.name.lower()
            ):
                suite = s
                break

        if not suite:
            print(f"{Colors.RED}❌ Test suite '{suite_name}' not found{Colors.RESET}")
            available = [s.file.replace(".py", "").replace("test_", "") for s in TEST_SUITES]
            print(f"{Colors.YELLOW}Available suites: {', '.join(available)}{Colors.RESET}")
            return False

        result = self.run_test_suite(suite)
        self.results.append(result)

        print("")  # Add spacing
        return result.success

    def run_all_suites(self) -> bool:
        """Run all test suites"""
        print(f"{Colors.BLUE}{Colors.BRIGHT}Running all test suites...{Colors.RESET}\n")

        for suite in TEST_SUITES:
            result = self.run_test_suite(suite)
            self.results.append(result)
            print("")  # Add spacing between tests

        # Print summary
        self.print_summary()

        return all(result.success for result in self.results)

    def print_summary(self):
        """Print test execution summary"""
        total_duration = time.time() - self.start_time
        passed = sum(1 for r in self.results if r.success)
        failed = len(self.results) - passed

        print(f"{Colors.BRIGHT}═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BRIGHT}📊 Test Summary{Colors.RESET}")
        print(f"{Colors.BRIGHT}═══════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"Total test suites: {len(self.results)}")
        print(f"{Colors.GREEN}✅ Passed: {passed}{Colors.RESET}")
        print(f"{Colors.RED}❌ Failed: {failed}{Colors.RESET}")
        print(f"Total duration: {total_duration:.0f}ms")

        if failed > 0:
            print(f"\n{Colors.RED}{Colors.BRIGHT}Failed test suites:{Colors.RESET}")
            for result in self.results:
                if not result.success:
                    print(f"{Colors.RED}  • {result.suite.file}{Colors.RESET}")

        print(f"{Colors.BRIGHT}═══════════════════════════════════════════════════════════════{Colors.RESET}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="TAC Protocol Python SDK Test Runner")
    parser.add_argument("suite", nargs="?", help="Test suite to run (or 'list' to show available)")
    parser.add_argument("--list", action="store_true", help="List available test suites")

    args = parser.parse_args()

    runner = TestRunner()
    runner.print_banner()

    if args.list or args.suite == "list":
        runner.list_test_suites()
        return

    if args.suite == "help" or args.suite == "--help":
        runner.print_usage()
        return

    if args.suite:
        # Run specific suite
        success = runner.run_single_suite(args.suite)
        sys.exit(0 if success else 1)
    else:
        # Run all suites
        success = runner.run_all_suites()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
