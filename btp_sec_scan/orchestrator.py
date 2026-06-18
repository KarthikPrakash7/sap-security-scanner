from __future__ import annotations
from pathlib import Path

from btp_sec_scan.models import Finding, ScanResult
from btp_sec_scan.scanners.btp_rules import BTPRulesScanner
from btp_sec_scan.scanners.gitleaks import GitleaksScanner
from btp_sec_scan.scanners.trivy import TrivyScanner


class Orchestrator:
    def __init__(
        self,
        trivy_path: str = "trivy",
        gitleaks_path: str = "gitleaks",
        rules_dir: Path | None = None,
    ) -> None:
        self._trivy = TrivyScanner(trivy_path)
        self._gitleaks = GitleaksScanner(gitleaks_path)
        self._btp = BTPRulesScanner(rules_dir)

    def scan(self, path: Path) -> ScanResult:
        trivy_findings, trivy_errors = self._trivy.scan(path)
        gitleaks_findings, gitleaks_errors = self._gitleaks.scan(path)
        btp_findings = self._btp.scan(path)

        all_findings: list[Finding] = trivy_findings + gitleaks_findings + btp_findings
        all_errors = trivy_errors + gitleaks_errors

        seen: set[tuple[str, str]] = set()
        deduped: list[Finding] = []
        for f in all_findings:
            key = (f.rule_id, f.file_path)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return ScanResult(findings=deduped, scan_path=str(path), scanner_errors=all_errors)
