from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Remediation:
    explanation: str
    fix_template: str
    effort: str  # "low" | "medium" | "high"
    docs_url: str | None = None


@dataclass
class Finding:
    id: str
    severity: Severity
    message: str
    file_path: str
    rule_id: str
    line: int | None = None
    remediation: Remediation | None = None


@dataclass
class ScanResult:
    findings: list[Finding]
    scan_path: str
    scanner_errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def exit_code(self) -> int:
        if self.scanner_errors:
            return 3
        if self.critical_count > 0:
            return 1
        if self.high_count > 0:
            return 2
        return 0
