from __future__ import annotations
import json
import os
import subprocess
import tempfile
from pathlib import Path

from sap_sec_scan.models import Finding, Remediation, Severity

# CycloneDX VDR ratings use lowercase severity strings.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.INFO,
}


class DepScanScanner:
    """OWASP dep-scan engine — SCA with reachability, additive to Trivy.

    Runs ``depscan`` against a source dir, then parses the CycloneDX VDR
    report(s) it writes. The output filename is not stable across dep-scan
    versions, so we glob ``*.vdr.json`` rather than hardcoding a name.
    """

    def __init__(self, depscan_path: str = "depscan", offline: bool = False) -> None:
        self._depscan_path = depscan_path
        self._offline = offline

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        # Prevent cdxgen from downloading language runtimes or executing build tools
        # against the scanned project (e.g. running gradle/mvn/npm install).
        env["CDXGEN_NO_INSTALL"] = "true"
        env["CDXGEN_SKIP_EXEC"] = "true"
        env["FETCH_LICENSE"] = "false"
        if self._offline:
            env["DEPSCAN_NO_AUTO_UPDATE"] = "1"
        return env

    def scan(self, path: Path) -> tuple[list[Finding], list[str]]:
        with tempfile.TemporaryDirectory(prefix="depscan-") as reports_dir:
            try:
                result = subprocess.run(
                    [self._depscan_path, "--src", str(path),
                     "--reports-dir", reports_dir, "--no-suggest"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env=self._build_env(),
                )
            except FileNotFoundError:
                return [], [f"depscan not found at '{self._depscan_path}' — install with 'pip install owasp-depscan'"]
            except subprocess.TimeoutExpired:
                return [], ["depscan scan timed out after 300 seconds"]

            vdr_files = sorted(Path(reports_dir).glob("*.vdr.json"))
            if not vdr_files:
                if result.returncode != 0:
                    return [], [f"depscan produced no VDR report (exit {result.returncode}): {result.stderr[:200]}"]
                # Exit 0 with no VDR is ambiguous: either genuinely clean, or the
                # SBOM step silently failed (depscan defaults to Dockerized cdxgen,
                # which produces no BOM if Docker/cdxgen is unavailable). A BOM file
                # distinguishes the two — no BOM means a setup problem, not "clean".
                if not list(Path(reports_dir).glob("*.cdx.json")):
                    if self._offline:
                        return [], [
                            "depscan ran in offline mode but produced no SBOM — "
                            "vulnerability database may be missing or stale. Run once without "
                            "--depscan-offline to seed the database, or set DEPSCAN_HOME to a "
                            "pre-populated database directory."
                        ]
                    return [], [
                        "depscan ran but produced no SBOM — no vulnerabilities could be "
                        "assessed. Install cdxgen ('npm install -g @cyclonedx/cdxgen') or "
                        "ensure Docker is available. See https://github.com/owasp-dep-scan/dep-scan"
                    ]
                return [], []  # BOM built, no vulnerabilities matched — genuinely clean

            findings: list[Finding] = []
            for vdr in vdr_files:
                try:
                    data = json.loads(vdr.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                for vuln in data.get("vulnerabilities") or []:
                    parsed = self._parse_vuln(vuln)
                    if parsed:
                        findings.append(parsed)
            return findings, []

    def _parse_vuln(self, vuln: dict) -> Finding | None:
        vuln_id = vuln.get("id")
        if not vuln_id:
            return None

        severity = self._max_severity(vuln.get("ratings") or [])
        package = self._affected_ref(vuln.get("affects") or [])
        recommendation = vuln.get("recommendation") or "no fix recommendation available"
        reachable = self._is_reachable(vuln.get("properties") or [])

        suffix = " [reachable]" if reachable else ""
        return Finding(
            id=vuln_id,
            severity=severity,
            message=f"{package} — {vuln_id} (fix: {recommendation}){suffix}",
            file_path=package,
            rule_id=vuln_id,
            remediation=Remediation(
                explanation=(vuln.get("description") or "")[:500],
                fix_template=recommendation,
                effort="low" if recommendation != "no fix recommendation available" else "high",
            ),
        )

    @staticmethod
    def _max_severity(ratings: list[dict]) -> Severity:
        best = Severity.INFO
        for rating in ratings:
            sev = _SEVERITY_MAP.get(str(rating.get("severity", "")).lower(), Severity.INFO)
            if sev > best:
                best = sev
        return best

    @staticmethod
    def _affected_ref(affects: list[dict]) -> str:
        for entry in affects:
            ref = entry.get("ref")
            if ref:
                return str(ref)
        return "unknown-package"

    @staticmethod
    def _is_reachable(properties: list[dict]) -> bool:
        for prop in properties:
            name = str(prop.get("name", "")).lower()
            if "reachab" in name and str(prop.get("value", "")).lower() in ("true", "yes", "reachable"):
                return True
        return False
