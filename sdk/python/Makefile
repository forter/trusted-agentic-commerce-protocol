.PHONY: help test test-all test-crypto test-cache test-network test-sender test-recipient test-errors test-integration test-utils test-list lint format format-check type-check clean install-dev fix lint-fix dev

help:
	@echo "Available commands:"
	@echo "  test           Run all tests"
	@echo "  test-all       Run all tests (alias for test)"
	@echo "  test-crypto    Run crypto tests"
	@echo "  test-cache     Run cache tests"
	@echo "  test-network   Run network tests"
	@echo "  test-sender    Run sender tests"
	@echo "  test-recipient Run recipient tests"
	@echo "  test-errors    Run error tests"
	@echo "  test-integration Run integration tests"
	@echo "  test-utils     Run utils tests"
	@echo "  test-list      List available test modules"
	@echo "  format         Format code with black and isort"
	@echo "  format-check   Check formatting without making changes"
	@echo "  lint           Lint with flake8"
	@echo "  lint-fix       Auto-fix formatting then show remaining lint issues"
	@echo "  type-check     Type checking with mypy"
	@echo "  clean          Clean up generated files"
	@echo "  install-dev    Install development dependencies"
	@echo "  fix            Format and fix linting issues (alias for lint-fix)"
	@echo "  dev            Run full development workflow"

# Test commands
test:
	python tests/test_runner.py

test-all:
	python tests/test_runner.py

test-crypto:
	python tests/test_runner.py crypto

test-cache:
	python tests/test_runner.py cache

test-network:
	python tests/test_runner.py network

test-sender:
	python tests/test_runner.py sender

test-recipient:
	python tests/test_runner.py recipient

test-errors:
	python tests/test_runner.py errors

test-integration:
	python tests/test_runner.py integration

test-utils:
	python tests/test_runner.py utils

test-list:
	python tests/test_runner.py list

# Install development dependencies
install-dev:
	pip install -r requirements-dev.txt

# Format code with black and isort
format:
	black src/ tests/
	isort src/ tests/

# Check formatting without making changes
format-check:
	black --check src/ tests/
	isort --check-only src/ tests/

# Lint with flake8
lint:
	flake8 src/ tests/

# Type checking with mypy  
type-check:
	mypy src/

# Fix all formatting and linting issues
fix:
	black src/ tests/
	isort src/ tests/

# Automatically fix what can be fixed, then show remaining issues
lint-fix: fix
	@echo "Running linter after auto-fixes..."
	-flake8 src/ tests/ || echo "Some linting issues remain - please review above"

# Clean up generated files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +

# Development workflow - run all checks and tests
dev: clean format lint type-check test