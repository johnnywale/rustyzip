"""Pytest configuration for rustyzipper tests."""

import pytest


def pytest_addoption(parser):
    """Add --run-slow option to pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests (large binary encryption tests)",
    )


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow")


def pytest_collection_modifyitems(config, items):
    """Skip slow tests unless --run-slow is passed."""
    if config.getoption("--run-slow"):
        # --run-slow given in cli: do not skip slow tests
        return

    skip_slow = pytest.mark.skip(reason="need --run-slow option to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)
