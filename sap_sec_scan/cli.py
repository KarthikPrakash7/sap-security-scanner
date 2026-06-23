from __future__ import annotations
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from sap_sec_scan.models import Severity, ScanResult
from sap_sec_scan.orchestrator import Orchestrator
from sap_sec_scan.output import format_json, format_sarif, format_table

app = typer.Typer(name="sap-sec-scan", help="Security vulnerability scanner for SAP BTP app packages")


class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    sarif = "sarif"


class Threshold(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


def _effective_exit_code(result: ScanResult, threshold: Threshold) -> int:
    if result.scanner_errors:
        return 3
    severity_floor = {
        Threshold.CRITICAL: Severity.CRITICAL,
        Threshold.HIGH: Severity.HIGH,
        Threshold.MEDIUM: Severity.MEDIUM,
    }[threshold]
    breaching = [f for f in result.findings if f.severity >= severity_floor]
    if any(f.severity == Severity.CRITICAL for f in breaching):
        return 1
    if breaching:
        return 2
    return 0


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Path to MTA/CAP project directory", exists=True)],
    format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.table,
    threshold: Annotated[Threshold, typer.Option("--threshold")] = Threshold.HIGH,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Accepted for compatibility — LLM not used in core scanner")] = False,
    depscan: Annotated[bool, typer.Option("--depscan", help="Also run OWASP dep-scan (reachability-aware SCA; requires 'owasp-depscan')")] = False,
    trivy_path: Annotated[str, typer.Option(hidden=True)] = "trivy",
    gitleaks_path: Annotated[str, typer.Option(hidden=True)] = "gitleaks",
    depscan_path: Annotated[str, typer.Option(hidden=True)] = "depscan",
) -> None:
    orchestrator = Orchestrator(
        trivy_path=trivy_path,
        gitleaks_path=gitleaks_path,
        depscan_path=depscan_path,
        use_depscan=depscan,
    )
    result = orchestrator.scan(path)

    if format == OutputFormat.json:
        print(format_json(result))
    elif format == OutputFormat.sarif:
        print(format_sarif(result))
    else:
        print(format_table(result))

    sys.exit(_effective_exit_code(result, threshold))
