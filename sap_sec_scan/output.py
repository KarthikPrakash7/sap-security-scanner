from __future__ import annotations
import dataclasses
import io
import json
import os

from rich.console import Console
from rich.table import Table
from rich import box

from sap_sec_scan import __version__
from sap_sec_scan.models import ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

# SARIF result.level — GitHub code scanning recognizes error/warning/note.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub Security tab ranks by numeric security-severity (0.0–10.0).
_SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def format_json(result: ScanResult) -> str:
    def _serialize(obj):
        if isinstance(obj, Severity):
            return obj.name
        return str(obj)

    def _convert_findings(findings):
        converted = []
        for f in findings:
            f_dict = dataclasses.asdict(f)
            f_dict["severity"] = f.severity.name
            converted.append(f_dict)
        return converted

    payload = {
        "scan_path": result.scan_path,
        "exit_code": result.exit_code,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "total": len(result.findings),
        },
        "findings": _convert_findings(result.findings),
        "scanner_errors": result.scanner_errors,
    }
    return json.dumps(payload, default=_serialize, indent=2)


def _sarif_uri(file_path: str, scan_path: str) -> str:
    """Return a repo-relative POSIX URI so GitHub maps the result to a source file."""
    try:
        rel = os.path.relpath(file_path, scan_path)
    except ValueError:
        # Different drive on Windows, or non-path file_path — fall back to raw value.
        return file_path
    if rel.startswith(".."):
        return file_path
    return rel.replace(os.sep, "/")


def format_sarif(result: ScanResult) -> str:
    """Render findings as SARIF 2.1.0 for GitHub code scanning / PR annotations."""
    rules: dict[str, dict] = {}
    rule_index: dict[str, int] = {}
    sarif_results: list[dict] = []

    for f in result.findings:
        if f.rule_id not in rules:
            rule_index[f.rule_id] = len(rules)
            descriptor = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "security-severity": _SARIF_SECURITY_SEVERITY[f.severity],
                },
            }
            if f.remediation and f.remediation.docs_url:
                descriptor["helpUri"] = f.remediation.docs_url
            if f.remediation and f.remediation.explanation:
                descriptor["fullDescription"] = {"text": f.remediation.explanation}
            rules[f.rule_id] = descriptor

        region = {"startLine": f.line} if f.line else {"startLine": 1}
        sarif_results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(f.file_path, result.scan_path)},
                    "region": region,
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sap-security-scanner",
                    "version": __version__,
                    "informationUri": "https://github.com/KarthikPrakash7/sap-security-scanner",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)


def format_table(result: ScanResult) -> str:
    console = Console(record=True, file=io.StringIO(), width=120)

    if not result.findings and not result.scanner_errors:
        console.print("[bold green]✓ No security findings — clean[/bold green]")
        return console.export_text()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("File", style="dim")
    table.add_column("Finding")

    for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
        color = _SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(f.rule_id, f"[{color}]{f.severity}[/{color}]", f.file_path, f.message[:80])

    console.print(table)

    parts = []
    if result.critical_count:
        parts.append(f"[bold red]{result.critical_count} CRITICAL[/bold red]")
    if result.high_count:
        parts.append(f"[red]{result.high_count} HIGH[/red]")
    other = len(result.findings) - result.critical_count - result.high_count
    if other:
        parts.append(f"{other} other")
    console.print(" ".join(parts))

    for err in result.scanner_errors:
        console.print(f"[yellow]⚠ Scanner error: {err}[/yellow]")

    return console.export_text()
