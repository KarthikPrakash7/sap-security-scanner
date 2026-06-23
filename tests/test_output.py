import json
from btp_sec_scan.models import Finding, Remediation, ScanResult, Severity
from btp_sec_scan.output import format_json, format_sarif, format_table


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


def test_format_sarif_shape_empty():
    sarif = json.loads(format_sarif(_make_result()))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "btp-security-scanner"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_format_sarif_level_mapping():
    findings = [
        Finding(id="C", severity=Severity.CRITICAL, message="c", file_path="a.json", rule_id="R-C"),
        Finding(id="M", severity=Severity.MEDIUM, message="m", file_path="a.json", rule_id="R-M"),
        Finding(id="L", severity=Severity.LOW, message="l", file_path="a.json", rule_id="R-L"),
    ]
    sarif = json.loads(format_sarif(_make_result(findings=findings)))
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels == {"R-C": "error", "R-M": "warning", "R-L": "note"}


def test_format_sarif_relative_uri_and_region():
    f = Finding(id="X", severity=Severity.HIGH, message="m", file_path="/test/path/sub/xs-app.json", rule_id="R-X", line=7)
    sarif = json.loads(format_sarif(_make_result(findings=[f])))
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "sub/xs-app.json"
    assert loc["region"]["startLine"] == 7


def test_format_sarif_dedups_rules_and_carries_metadata():
    rem = Remediation(explanation="why", fix_template="fix", effort="low", docs_url="https://help.sap.com/x")
    findings = [
        Finding(id="A", severity=Severity.HIGH, message="dup", file_path="a.json", rule_id="R-A", remediation=rem),
        Finding(id="A2", severity=Severity.HIGH, message="dup", file_path="b.json", rule_id="R-A", remediation=rem),
    ]
    sarif = json.loads(format_sarif(_make_result(findings=findings)))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["helpUri"] == "https://help.sap.com/x"
    assert rules[0]["properties"]["security-severity"] == "7.0"
    assert len(sarif["runs"][0]["results"]) == 2
