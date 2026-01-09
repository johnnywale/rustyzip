# Makefile for rustyzipper

.PHONY: all venv install dev build test test-verbose clean help

# Default Python and venv paths
VENV := .venv
PYTHON := $(VENV)/Scripts/python
MATURIN := $(VENV)/Scripts/maturin
PYTEST := $(VENV)/Scripts/pytest

# Export for maturin
export VIRTUAL_ENV := $(CURDIR)/$(VENV)

all: dev test

# Create virtual environment
venv:
	@if not exist $(VENV) python -m venv $(VENV)

# Install dependencies
install: venv
	$(PYTHON) -m pip install maturin pytest

# Build and install in development mode
dev: install
	$(MATURIN) develop

# Build release wheel
build: install
	$(MATURIN) build --release

# Run tests
test:
	$(PYTEST) python/tests

# Run tests with verbose output
test-verbose:
	$(PYTEST) python/tests -v

# Run tests with coverage
test-cov:
	$(PYTHON) -m pip install pytest-cov
	$(PYTEST) python/tests --cov=rustyzipper --cov-report=term-missing

# Run specific test file
test-compression:
	$(PYTEST) python/tests/test_compression.py -v

test-compat:
	$(PYTEST) python/tests/test_pyminizip_compat.py -v

# Clean build artifacts
clean:
	cargo clean
	-rm -rf $(VENV)
	-rm -rf target
	-rm -rf *.egg-info
	-rm -rf dist
	-rm -rf build
	-rm -rf .pytest_cache
	-rm -rf python/rustyzipper/__pycache__
	-rm -rf python/tests/__pycache__

# Format code
fmt:
	cargo fmt

# Lint Rust code
lint:
	cargo clippy

# Run Rust tests
test-rust:
	cargo test

# Help
help:
	@echo "Available targets:"
	@echo "  make venv         - Create virtual environment"
	@echo "  make install      - Install dependencies"
	@echo "  make dev          - Build and install in dev mode"
	@echo "  make build        - Build release wheel"
	@echo "  make test         - Run all Python tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make test-cov     - Run tests with coverage"
	@echo "  make test-compression - Run compression tests only"
	@echo "  make test-compat  - Run compatibility tests only"
	@echo "  make test-rust    - Run Rust tests"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make fmt          - Format Rust code"
	@echo "  make lint         - Lint Rust code"
	@echo "  make help         - Show this help"
