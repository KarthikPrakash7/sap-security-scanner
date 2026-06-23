from __future__ import annotations
import dataclasses
import json
from pathlib import Path

from fastmcp import FastMCP

from sap_sec_scan.models import Severity
from sap_sec_scan.orchestrator import Orchestrator
from sap_sec_scan.output import format_json
from sap_sec_scan.scanners.btp_rules import BTPRulesScanner

mcp = FastMCP("sap-security-scanner")


def _serialize(obj):
    if isinstance(obj, Severity):
        return obj.name
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    return str(obj)


@mcp.tool()
def scan_project(
    path: str,
    threshold: str = "HIGH",
    trivy_path: str = "trivy",
    gitleaks_path: str = "gitleaks",
) -> str:
    """Scan a BTP project directory for CVEs, secrets, and BTP misconfigurations."""
    result = Orchestrator(trivy_path=trivy_path, gitleaks_path=gitleaks_path).scan(Path(path))
    return format_json(result)


@mcp.tool()
def scan_file(file_path: str) -> str:
    """Run BTP rules against a single file (xs-security.json, mta.yaml, .cds)."""
    path = Path(file_path)
    findings = BTPRulesScanner().scan(path.parent)
    findings = [f for f in findings if path.name in f.file_path]
    return json.dumps([dataclasses.asdict(f) for f in findings], default=_serialize, indent=2)


@mcp.tool()
def list_rules(category: str = "all") -> str:
    """List available BTP security rules. category: xsuaa|mta|cap|all"""
    rules = BTPRulesScanner()._rules
    if category != "all":
        rules = [r for r in rules if category.upper() in r["id"]]
    return json.dumps(
        [{"id": r["id"], "severity": r["severity"], "message": r["message"]} for r in rules],
        indent=2,
    )


@mcp.tool()
def explain_finding(rule_id: str) -> str:
    """Get full remediation details for a specific rule ID."""
    rule = next((r for r in BTPRulesScanner()._rules if r["id"] == rule_id), None)
    if not rule:
        return json.dumps({"error": f"Rule '{rule_id}' not found. Use list_rules() to see available rules."})
    rem = rule.get("remediation", {})
    return json.dumps({
        "rule_id": rule_id,
        "severity": rule["severity"],
        "message": rule["message"],
        "explanation": rem.get("explanation", ""),
        "fix_template": rem.get("fix_template", ""),
        "effort": rem.get("effort", "medium"),
        "docs_url": rem.get("docs_url"),
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
