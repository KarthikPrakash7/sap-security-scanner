from __future__ import annotations
import json
import subprocess
from pathlib import Path

from btp_sec_scan.models import Finding, Remediation, Severity

_SECRET_REMEDIATION = Remediation(
    explanation="Hardcoded credentials in source code can be extracted from git history even after deletion. Rotate the secret immediately.",
    fix_template=(
        "1. Remove the secret from source and git history (git-filter-repo or BFG)\n"
        "2. Rotate the credential in SAP BTP cockpit\n"
        "3. Use environment variables or BTP Credential Store: "
        "https://help.sap.com/docs/credential-store"
    ),
    effort="high",
    docs_url="https://help.sap.com/docs/credential-store",
)


class GitleaksScanner:
    def __init__(self, gitleaks_path: str = "gitleaks") -> None:
        self._gitleaks_path = gitleaks_path

    def scan(self, path: Path) -> tuple[list[Finding], list[str]]:
        try:
            result = subprocess.run(
                [self._gitleaks_path, "detect", "--source", str(path),
                 "--report-format", "json", "--no-git"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            return [], [f"gitleaks not found at '{self._gitleaks_path}' — install from https://github.com/gitleaks/gitleaks"]
        except subprocess.TimeoutExpired:
            return [], ["gitleaks scan timed out after 60 seconds"]

        if not result.stdout.strip() or result.stdout.strip() == "null":
            return [], []

        try:
            leaks = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [], [f"gitleaks returned invalid JSON: {result.stderr[:200]}"]

        if not leaks:
            return [], []

        return [self._parse_leak(leak) for leak in leaks], []

    def _parse_leak(self, leak: dict) -> Finding:
        match_preview = leak.get("Match", "")[:20] + "****"
        return Finding(
            id=f"SECRET-{leak.get('RuleID', 'unknown')}",
            severity=Severity.CRITICAL,
            message=f"{leak.get('Description', 'Secret detected')} in {leak.get('File', 'unknown')} (preview: {match_preview})",
            file_path=leak.get("File", "unknown"),
            rule_id=f"SECRET-{leak.get('RuleID', 'unknown')}",
            line=leak.get("StartLine"),
            remediation=_SECRET_REMEDIATION,
        )
