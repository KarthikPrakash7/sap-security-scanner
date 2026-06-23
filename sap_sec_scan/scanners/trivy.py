from __future__ import annotations
import json
import subprocess
from pathlib import Path

from sap_sec_scan.models import Finding, Remediation, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner:
    def __init__(self, trivy_path: str = "trivy") -> None:
        self._trivy_path = trivy_path

    def scan(self, path: Path) -> tuple[list[Finding], list[str]]:
        try:
            result = subprocess.run(
                [self._trivy_path, "fs", "--format", "json", "--scanners", "vuln", str(path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return [], [f"trivy not found at '{self._trivy_path}' — install from https://aquasecurity.github.io/trivy/"]
        except subprocess.TimeoutExpired:
            return [], ["trivy scan timed out after 120 seconds"]

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [], [f"trivy returned invalid JSON: {result.stderr[:200]}"]

        findings: list[Finding] = []
        for scan_result in data.get("Results", []):
            for vuln in scan_result.get("Vulnerabilities") or []:
                findings.append(self._parse_vuln(vuln, scan_result["Target"]))
        return findings, []

    def _parse_vuln(self, vuln: dict, target: str) -> Finding:
        fixed = vuln.get("FixedVersion", "no fix available")
        remediation = Remediation(
            explanation=vuln.get("Description", "")[:500],
            fix_template=f"Upgrade {vuln['PkgName']} from {vuln['InstalledVersion']} to {fixed}",
            effort="low" if fixed != "no fix available" else "high",
        )
        return Finding(
            id=vuln["VulnerabilityID"],
            severity=_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO),
            message=f"{vuln['PkgName']}@{vuln['InstalledVersion']} — {vuln['VulnerabilityID']} (fix: {fixed})",
            file_path=target,
            rule_id=vuln["VulnerabilityID"],
            remediation=remediation,
        )
