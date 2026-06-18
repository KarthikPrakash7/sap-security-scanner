import json
import pytest
from unittest.mock import patch
from pathlib import Path
from btp_sec_scan.models import Finding, ScanResult, Severity


def test_scan_project_returns_json():
    from btp_sec_scan.mcp_server import scan_project
    with patch("btp_sec_scan.mcp_server.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.return_value = ScanResult(findings=[], scan_path="/fake")
        result = scan_project(path="/fake")
    data = json.loads(result)
    assert "findings" in data
    assert data["exit_code"] == 0


def test_scan_file_returns_findings():
    from btp_sec_scan.mcp_server import scan_file
    with patch("btp_sec_scan.mcp_server.BTPRulesScanner") as MockBTP:
        MockBTP.return_value.scan.return_value = [
            Finding(id="BTP-XSUAA-001", severity=Severity.HIGH, message="test",
                    file_path="/fake/xs-security.json", rule_id="BTP-XSUAA-001")
        ]
        result = scan_file(file_path="/fake/xs-security.json")
    data = json.loads(result)
    assert len(data) == 1
    assert data[0]["rule_id"] == "BTP-XSUAA-001"


def test_list_rules_returns_all():
    from btp_sec_scan.mcp_server import list_rules
    result = list_rules(category="all")
    data = json.loads(result)
    assert len(data) > 0
    assert all("id" in r and "severity" in r for r in data)


def test_explain_finding_returns_remediation():
    from btp_sec_scan.mcp_server import explain_finding
    result = explain_finding(rule_id="BTP-XSUAA-001")
    data = json.loads(result)
    assert "explanation" in data
    assert "fix_template" in data


def test_explain_finding_unknown_rule():
    from btp_sec_scan.mcp_server import explain_finding
    result = explain_finding(rule_id="DOES-NOT-EXIST")
    data = json.loads(result)
    assert "error" in data
