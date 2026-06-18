import pytest

def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires Trivy and Gitleaks installed")
