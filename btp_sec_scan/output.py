from __future__ import annotations
import dataclasses
import json

from rich.console import Console
from rich.table import Table
from rich import box

from btp_sec_scan.models import ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def format_json(result: ScanResult) -> str:
    def _serialize(obj):
        if isinstance(obj, Severity):
            return obj.name
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return str(obj)

    def _convert_findings(findings):
        converted = []
        for f in findings:
            f_dict = dataclasses.asdict(f)
            f_dict["severity"] = f.severity.name
            if f_dict["remediation"]:
                f_dict["remediation"] = dataclasses.asdict(f_dict["remediation"])
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


def format_table(result: ScanResult) -> str:
    console = Console(record=True, width=120)

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
