import json
from btp_sec_scan.models import Finding, ScanResult, Severity
from btp_sec_scan.output import format_json, format_table


def _make_result(findings=None, errors=None):
    return ScanResult(findings=findings or [], scan_path="/test/path", scanner_errors=errors or [])


def test_format_json_empty():
    output = json.loads(format_json(_make_result()))
    assert output["findings"] == []
    assert output["exit_code"] == 0


def test_format_json_with_findings():
    f = Finding(id="CVE-1", severity=Severity.CRITICAL, message="test vuln", file_path="pkg.json", rule_id="CVE-1")
    output = json.loads(format_json(_make_result(findings=[f])))
    assert len(output["findings"]) == 1
    assert output["findings"][0]["severity"] == "CRITICAL"
    assert output["exit_code"] == 1


def test_format_table_contains_rule_id():
    f = Finding(id="BTP-XSUAA-001", severity=Severity.HIGH, message="wildcard auth", file_path="xs-security.json", rule_id="BTP-XSUAA-001")
    table = format_table(_make_result(findings=[f]))
    assert "BTP-XSUAA-001" in table
    assert "HIGH" in table


def test_format_table_clean():
    table = format_table(_make_result())
    assert "clean" in table.lower() or "no findings" in table.lower()
