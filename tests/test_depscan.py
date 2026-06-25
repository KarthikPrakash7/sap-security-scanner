import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from sap_sec_scan.scanners.depscan import DepScanScanner
from sap_sec_scan.models import Severity

# CycloneDX VDR shape that depscan writes to <reports-dir>/*.vdr.json
VDR_OUTPUT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "vulnerabilities": [
        {
            "id": "CVE-2024-9999",
            "ratings": [
                {"severity": "medium", "score": 5.3},
                {"severity": "critical", "score": 9.8},
            ],
            "affects": [{"ref": "pkg:npm/lodash@4.17.15"}],
            "recommendation": "Update to 4.17.21 or later",
            "description": "Prototype pollution in lodash",
            "properties": [{"name": "depscan:insights", "value": "Reachable"},
                           {"name": "depscan:reachability", "value": "true"}],
        },
        {
            "id": "CVE-2024-1111",
            "ratings": [{"severity": "low"}],
            "affects": [{"ref": "pkg:pypi/requests@2.19.0"}],
            "recommendation": "Update to 2.31.0",
            "description": "Info leak",
        },
    ],
}


def _run_scanner(vdr_data, returncode=1, write_report=True, write_bom=True, offline=False):
    """Patch subprocess.run and the temp report dir so glob finds our reports.

    write_report -> VDR (sbom-universal.vdr.json); write_bom -> SBOM
    (sbom-universal.cdx.json), which depscan always emits when its BOM step runs.
    """
    def fake_run(*args, **kwargs):
        reports_dir = args[0][args[0].index("--reports-dir") + 1]
        if write_bom:
            Path(reports_dir, "sbom-universal.cdx.json").write_text('{"components": []}')
        if write_report:
            Path(reports_dir, "sbom-universal.vdr.json").write_text(json.dumps(vdr_data))
        return MagicMock(returncode=returncode, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        return DepScanScanner(offline=offline).scan(Path("/fake/path"))


def test_depscan_parses_vulnerabilities():
    findings, errors = _run_scanner(VDR_OUTPUT)
    assert errors == []
    assert {f.id for f in findings} == {"CVE-2024-9999", "CVE-2024-1111"}


def test_depscan_takes_highest_severity_rating():
    findings, _ = _run_scanner(VDR_OUTPUT)
    crit = next(f for f in findings if f.id == "CVE-2024-9999")
    assert crit.severity == Severity.CRITICAL  # max(medium, critical)


def test_depscan_marks_reachable():
    findings, _ = _run_scanner(VDR_OUTPUT)
    crit = next(f for f in findings if f.id == "CVE-2024-9999")
    assert "[reachable]" in crit.message
    low = next(f for f in findings if f.id == "CVE-2024-1111")
    assert "[reachable]" not in low.message


def test_depscan_uses_purl_as_file_path():
    findings, _ = _run_scanner(VDR_OUTPUT)
    crit = next(f for f in findings if f.id == "CVE-2024-9999")
    assert crit.file_path == "pkg:npm/lodash@4.17.15"


def test_depscan_not_installed_returns_error():
    with patch("subprocess.run", side_effect=FileNotFoundError("depscan not found")):
        findings, errors = DepScanScanner().scan(Path("/fake/path"))
    assert findings == []
    assert len(errors) == 1
    assert "depscan" in errors[0].lower()


def test_depscan_bom_but_no_vulns_is_clean():
    # SBOM built, no VDR, exit 0 -> genuinely clean
    findings, errors = _run_scanner(VDR_OUTPUT, returncode=0, write_report=False, write_bom=True)
    assert findings == []
    assert errors == []


def test_depscan_no_bom_warns_setup_problem():
    # No SBOM and no VDR on a clean exit -> silent setup failure, must warn
    findings, errors = _run_scanner(VDR_OUTPUT, returncode=0, write_report=False, write_bom=False)
    assert findings == []
    assert len(errors) == 1
    assert "no SBOM" in errors[0]
    assert "cdxgen" in errors[0]


def test_depscan_no_report_failed_exit_is_error():
    findings, errors = _run_scanner(VDR_OUTPUT, returncode=2, write_report=False, write_bom=False)
    assert findings == []
    assert len(errors) == 1
    assert "no VDR report" in errors[0]


def test_depscan_empty_vulnerabilities():
    findings, errors = _run_scanner({"vulnerabilities": []}, returncode=0)
    assert findings == []
    assert errors == []


def test_depscan_sets_cdxgen_hardening_env_vars():
    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs.get("env", {}))
        reports_dir = args[0][args[0].index("--reports-dir") + 1]
        Path(reports_dir, "sbom-universal.cdx.json").write_text('{"components": []}')
        Path(reports_dir, "sbom-universal.vdr.json").write_text(json.dumps(VDR_OUTPUT))
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=capture_run):
        DepScanScanner().scan(Path("/fake/path"))

    assert captured.get("CDXGEN_NO_INSTALL") == "true"
    assert captured.get("CDXGEN_SKIP_EXEC") == "true"
    assert captured.get("FETCH_LICENSE") == "false"


def test_depscan_offline_sets_no_auto_update():
    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs.get("env", {}))
        reports_dir = args[0][args[0].index("--reports-dir") + 1]
        Path(reports_dir, "sbom-universal.cdx.json").write_text('{"components": []}')
        Path(reports_dir, "sbom-universal.vdr.json").write_text(json.dumps(VDR_OUTPUT))
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=capture_run):
        DepScanScanner(offline=True).scan(Path("/fake/path"))

    assert captured.get("DEPSCAN_NO_AUTO_UPDATE") == "1"


def test_depscan_online_does_not_set_no_auto_update():
    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs.get("env", {}))
        reports_dir = args[0][args[0].index("--reports-dir") + 1]
        Path(reports_dir, "sbom-universal.cdx.json").write_text('{"components": []}')
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=capture_run):
        DepScanScanner(offline=False).scan(Path("/fake/path"))

    assert "DEPSCAN_NO_AUTO_UPDATE" not in captured


def test_depscan_offline_no_bom_warns_db_missing():
    def fake_run(*args, **kwargs):
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_run):
        findings, errors = DepScanScanner(offline=True).scan(Path("/fake/path"))

    assert findings == []
    assert len(errors) == 1
    assert "offline" in errors[0].lower()
    assert "database" in errors[0].lower()


@pytest.mark.integration
def test_depscan_real_scan_clean_project(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {}}')
    findings, errors = DepScanScanner().scan(tmp_path)
    assert errors == []
