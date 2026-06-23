from __future__ import annotations
from pathlib import Path

from sap_sec_scan.models import Finding, ScanResult
from sap_sec_scan.scanners.btp_rules import BTPRulesScanner
from sap_sec_scan.scanners.depscan import DepScanScanner
from sap_sec_scan.scanners.gitleaks import GitleaksScanner
from sap_sec_scan.scanners.trivy import TrivyScanner


class Orchestrator:
    def __init__(
        self,
        trivy_path: str = "trivy",
        gitleaks_path: str = "gitleaks",
        depscan_path: str = "depscan",
        rules_dir: Path | None = None,
        use_depscan: bool = False,
    ) -> None:
        self._trivy = TrivyScanner(trivy_path)
        self._gitleaks = GitleaksScanner(gitleaks_path)
        self._depscan = DepScanScanner(depscan_path)
        self._btp = BTPRulesScanner(rules_dir)
        self._use_depscan = use_depscan

    def scan(self, path: Path) -> ScanResult:
        trivy_findings, trivy_errors = self._trivy.scan(path)
        gitleaks_findings, gitleaks_errors = self._gitleaks.scan(path)
        btp_findings = self._btp.scan(path)

        depscan_findings: list[Finding] = []
        depscan_errors: list[str] = []
        if self._use_depscan:
            depscan_findings, depscan_errors = self._depscan.scan(path)

        all_findings: list[Finding] = (
            trivy_findings + gitleaks_findings + depscan_findings + btp_findings
        )
        all_errors = trivy_errors + gitleaks_errors + depscan_errors

        seen: set[tuple[str, str]] = set()
        deduped: list[Finding] = []
        for f in all_findings:
            key = (f.rule_id, f.file_path)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return ScanResult(findings=deduped, scan_path=str(path), scanner_errors=all_errors)
