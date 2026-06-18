import pytest
from pathlib import Path
from btp_sec_scan.scanners.btp_rules import BTPRulesScanner
from btp_sec_scan.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_project_no_findings():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_clean")
    assert findings == []


def test_xsuaa_wildcard_authority_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-001" in rule_ids


def test_xsuaa_shared_tenant_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-002" in rule_ids


def test_xsuaa_missing_xsappname_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-003" in rule_ids


def test_cap_missing_requires_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "cap_missing_auth")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-CAP-001" in rule_ids


def test_findings_have_remediation():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    for f in findings:
        assert f.remediation is not None
        assert f.remediation.explanation
        assert f.remediation.fix_template


def test_finding_severity_correct():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    xsuaa_001 = next(f for f in findings if f.rule_id == "BTP-XSUAA-001")
    assert xsuaa_001.severity == Severity.HIGH
