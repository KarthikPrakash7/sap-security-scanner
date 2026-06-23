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


def test_xsuaa_missing_role_templates_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-005" in rule_ids


def test_xsapp_missing_logout_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "xsapp_bad")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSAPP-002" in rule_ids


def test_xsapp_cors_wildcard_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "xsapp_bad")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSAPP-003" in rule_ids


def test_xsapp_missing_session_timeout_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "xsapp_bad")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSAPP-004" in rule_ids


def test_xsapp_missing_auth_method_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "xsapp_bad")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSAPP-005" in rule_ids


def test_clean_xsapp_no_findings():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_clean")
    assert findings == []


def test_token_validity_too_long_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-006" in rule_ids


def test_token_validity_within_limit_not_triggered():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_clean")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-006" not in rule_ids


def test_hardcoded_env_credential_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_env")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-MTA-002" in rule_ids


def test_mta_variable_reference_not_flagged():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_clean")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-MTA-002" not in rule_ids


def test_xsapp_csrf_disabled_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "xsapp_bad")
    assert "BTP-XSAPP-006" in [f.rule_id for f in findings]


def test_xsapp_plaintext_http_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "xsapp_bad")
    assert "BTP-XSAPP-007" in [f.rule_id for f in findings]


def test_xsapp_csrf_and_http_not_flagged_when_clean():
    scanner = BTPRulesScanner()
    rule_ids = [f.rule_id for f in scanner.scan(FIXTURES / "mta_clean")]
    assert "BTP-XSAPP-006" not in rule_ids
    assert "BTP-XSAPP-007" not in rule_ids


def test_xsuaa_wildcard_foreign_scope_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    assert "BTP-XSUAA-007" in [f.rule_id for f in findings]


def test_xsuaa_wildcard_foreign_scope_not_flagged_when_clean():
    scanner = BTPRulesScanner()
    rule_ids = [f.rule_id for f in scanner.scan(FIXTURES / "mta_clean")]
    assert "BTP-XSUAA-007" not in rule_ids


def test_insecure_destination_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_dest")
    assert "BTP-DEST-001" in [f.rule_id for f in findings]


def test_insecure_destination_not_flagged_when_clean():
    scanner = BTPRulesScanner()
    rule_ids = [f.rule_id for f in scanner.scan(FIXTURES / "mta_clean")]
    assert "BTP-DEST-001" not in rule_ids
