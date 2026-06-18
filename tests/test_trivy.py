import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from btp_sec_scan.scanners.trivy import TrivyScanner
from btp_sec_scan.models import Severity

TRIVY_JSON_OUTPUT = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-12345",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.21",
                    "Severity": "CRITICAL",
                    "Description": "Prototype pollution in lodash",
                }
            ],
        }
    ]
}


def test_trivy_parses_critical_cve():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(TRIVY_JSON_OUTPUT),
            stderr="",
        )
        scanner = TrivyScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert len(findings) == 1
    assert findings[0].id == "CVE-2024-12345"
    assert findings[0].severity == Severity.CRITICAL
    assert errors == []


def test_trivy_not_installed_returns_error():
    with patch("subprocess.run", side_effect=FileNotFoundError("trivy not found")):
        scanner = TrivyScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert len(errors) == 1
    assert "trivy" in errors[0].lower()


def test_trivy_no_vulnerabilities_returns_empty():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": [{"Target": "package.json", "Vulnerabilities": None}]}),
            stderr="",
        )
        scanner = TrivyScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert errors == []


@pytest.mark.integration
def test_trivy_real_scan_clean_project(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {}}')
    scanner = TrivyScanner()
    findings, errors = scanner.scan(tmp_path)
    assert errors == []
