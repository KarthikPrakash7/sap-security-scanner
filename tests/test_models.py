import pytest
from sap_sec_scan.models import Finding, Remediation, ScanResult, Severity


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW


def test_finding_defaults():
    f = Finding(
        id="CVE-2024-001",
        severity=Severity.HIGH,
        message="Test vuln",
        file_path="package.json",
        rule_id="CVE-2024-001",
    )
    assert f.line is None
    assert f.remediation is None


def test_scan_result_counts():
    findings = [
        Finding(id="1", severity=Severity.CRITICAL, message="c", file_path="f", rule_id="r"),
        Finding(id="2", severity=Severity.HIGH, message="h", file_path="f", rule_id="r"),
        Finding(id="3", severity=Severity.LOW, message="l", file_path="f", rule_id="r"),
    ]
    result = ScanResult(findings=findings, scan_path="/tmp/proj")
    assert result.critical_count == 1
    assert result.high_count == 1
    assert result.exit_code == 1  # CRITICAL present


def test_scan_result_exit_code_high_only():
    findings = [
        Finding(id="1", severity=Severity.HIGH, message="h", file_path="f", rule_id="r"),
    ]
    result = ScanResult(findings=findings, scan_path="/tmp/proj")
    assert result.exit_code == 2  # HIGH only


def test_scan_result_exit_code_clean():
    result = ScanResult(findings=[], scan_path="/tmp/proj")
    assert result.exit_code == 0


def test_scan_result_exit_code_scanner_error():
    result = ScanResult(findings=[], scan_path="/tmp/proj", scanner_errors=["trivy not found"])
    assert result.exit_code == 3
