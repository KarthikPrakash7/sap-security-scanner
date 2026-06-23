from typer.testing import CliRunner
from unittest.mock import patch
from sap_sec_scan.cli import app
from sap_sec_scan.models import Finding, ScanResult, Severity

runner = CliRunner()


def _mock_clean(path):
    return ScanResult(findings=[], scan_path=str(path))


def _mock_critical(path):
    return ScanResult(
        findings=[Finding(id="CVE-1", severity=Severity.CRITICAL, message="vuln", file_path="pkg.json", rule_id="CVE-1")],
        scan_path=str(path),
    )


def test_cli_exit_0_clean_project(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_clean
        result = runner.invoke(app, [str(tmp_path)])
    assert result.exit_code == 0


def test_cli_exit_1_critical_findings(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_critical
        result = runner.invoke(app, [str(tmp_path)])
    assert result.exit_code == 1


def test_cli_json_format_output(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_clean
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
    import json
    data = json.loads(result.output)
    assert "findings" in data
    assert data["exit_code"] == 0


def test_cli_no_llm_flag_accepted(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_clean
        result = runner.invoke(app, [str(tmp_path), "--no-llm"])
    assert result.exit_code == 0
