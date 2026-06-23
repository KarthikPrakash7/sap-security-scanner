import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from sap_sec_scan.scanners.gitleaks import GitleaksScanner
from sap_sec_scan.models import Severity

GITLEAKS_JSON_OUTPUT = [
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": ".env",
        "StartLine": 1,
        "Match": "SAP_CLIENTSECRET=abc1****",
    }
]


def test_gitleaks_parses_secret():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(GITLEAKS_JSON_OUTPUT),
            stderr="",
        )
        scanner = GitleaksScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].file_path == ".env"
    assert errors == []


def test_gitleaks_not_installed_returns_error():
    with patch("subprocess.run", side_effect=FileNotFoundError("gitleaks not found")):
        scanner = GitleaksScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert "gitleaks" in errors[0].lower()


def test_gitleaks_no_secrets_returns_empty():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
        scanner = GitleaksScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert errors == []
