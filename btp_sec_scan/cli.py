from __future__ import annotations
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from btp_sec_scan.orchestrator import Orchestrator
from btp_sec_scan.output import format_json, format_table

app = typer.Typer(name="btp-sec-scan", help="Security vulnerability scanner for SAP BTP app packages")


class OutputFormat(str, Enum):
    table = "table"
    json = "json"


class Threshold(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Path to MTA/CAP project directory", exists=True)],
    format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.table,
    threshold: Annotated[Threshold, typer.Option("--threshold")] = Threshold.HIGH,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Accepted for compatibility — LLM not used in core scanner")] = False,
    trivy_path: Annotated[str, typer.Option(hidden=True)] = "trivy",
    gitleaks_path: Annotated[str, typer.Option(hidden=True)] = "gitleaks",
) -> None:
    orchestrator = Orchestrator(trivy_path=trivy_path, gitleaks_path=gitleaks_path)
    result = orchestrator.scan(path)

    if format == OutputFormat.json:
        print(format_json(result))
    else:
        print(format_table(result))

    sys.exit(result.exit_code)
