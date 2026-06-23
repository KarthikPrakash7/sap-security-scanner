from pathlib import Path
from unittest.mock import patch
import pytest
from sap_sec_scan.orchestrator import Orchestrator
from sap_sec_scan.models import Finding, Severity


def _make_finding(id: str, severity: Severity) -> Finding:
    return Finding(id=id, severity=severity, message="test", file_path="f", rule_id=id)


def test_orchestrator_merges_findings():
    with patch("sap_sec_scan.orchestrator.TrivyScanner") as MockTrivy, \
         patch("sap_sec_scan.orchestrator.GitleaksScanner") as MockGitleaks, \
         patch("sap_sec_scan.orchestrator.BTPRulesScanner") as MockBTP:
        MockTrivy.return_value.scan.return_value = ([_make_finding("CVE-1", Severity.CRITICAL)], [])
        MockGitleaks.return_value.scan.return_value = ([_make_finding("SEC-1", Severity.CRITICAL)], [])
        MockBTP.return_value.scan.return_value = [_make_finding("BTP-1", Severity.HIGH)]

        result = Orchestrator().scan(Path("/fake"))

    assert len(result.findings) == 3
    assert result.critical_count == 2
    assert result.high_count == 1


def test_orchestrator_collects_scanner_errors():
    with patch("sap_sec_scan.orchestrator.TrivyScanner") as MockTrivy, \
         patch("sap_sec_scan.orchestrator.GitleaksScanner") as MockGitleaks, \
         patch("sap_sec_scan.orchestrator.BTPRulesScanner") as MockBTP:
        MockTrivy.return_value.scan.return_value = ([], ["trivy not found"])
        MockGitleaks.return_value.scan.return_value = ([], [])
        MockBTP.return_value.scan.return_value = []

        result = Orchestrator().scan(Path("/fake"))

    assert "trivy not found" in result.scanner_errors
    assert result.exit_code == 3


def test_orchestrator_deduplicates_findings():
    dup = _make_finding("CVE-1", Severity.CRITICAL)
    with patch("sap_sec_scan.orchestrator.TrivyScanner") as MockTrivy, \
         patch("sap_sec_scan.orchestrator.GitleaksScanner") as MockGitleaks, \
         patch("sap_sec_scan.orchestrator.BTPRulesScanner") as MockBTP:
        MockTrivy.return_value.scan.return_value = ([dup, dup], [])
        MockGitleaks.return_value.scan.return_value = ([], [])
        MockBTP.return_value.scan.return_value = []

        result = Orchestrator().scan(Path("/fake"))

    assert len(result.findings) == 1
