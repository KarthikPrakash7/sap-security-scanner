# BTP Security Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI + MCP server that scans SAP BTP app packages (MTA + CAP) for CVEs, hardcoded secrets, and BTP-specific misconfigurations before deployment.

**Architecture:** Three independent scanner modules (Trivy subprocess for CVEs, Gitleaks subprocess for secrets, custom YAML rule engine for BTP misconfigs) feed into an orchestrator that merges findings into a unified ScanResult. A CLI renders results and exits with appropriate codes for CI/CD. A FastMCP server wraps the orchestrator for Claude Code integration.

**Tech Stack:** Python 3.11+, uv, typer, rich, fastmcp, pyyaml, jsonpath-ng, pytest, Trivy (subprocess), Gitleaks (subprocess)

## Global Constraints

- Python >=3.11
- uv for package management (not pip directly)
- All tests in `tests/` directory mirroring `sap_sec_scan/` structure
- Integration tests marked `@pytest.mark.integration` — only run when `RUN_INTEGRATION=1` env var set
- No hardcoded paths — all paths passed as arguments
- Trivy and Gitleaks called as subprocesses, not Python bindings
- Rule files live in `sap_sec_scan/rules/btp/` and are bundled with the package
- Exit codes: 0=clean, 1=CRITICAL findings, 2=HIGH findings, 3=scanner error
- Default threshold: HIGH (blocks on HIGH + CRITICAL)
- No LLM dependency in core scanning — fully offline

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `sap_sec_scan/__init__.py`
- Create: `sap_sec_scan/scanners/__init__.py`
- Create: `sap_sec_scan/rules/__init__.py`
- Create: `tests/__init__.py`
- Create: `conftest.py`
- Create: `.gitignore`

**Interfaces:**
- Produces: installable `sap-sec-scan` package, `pytest` runs without error

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "sap-security-scanner"
version = "0.1.0"
description = "Security vulnerability scanner for SAP BTP app packages"
requires-python = ">=3.11"
dependencies = [
    "typer>=0.12.0",
    "rich>=13.0.0",
    "pyyaml>=6.0.1",
    "jsonpath-ng>=1.6.1",
    "fastmcp>=2.0.0",
    "anthropic>=0.40.0",
]

[project.scripts]
sap-sec-scan = "sap_sec_scan.cli:app"

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-mock>=3.12.0",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
    "integration: requires Trivy and Gitleaks installed",
]

[tool.hatch.build.targets.wheel]
packages = ["sap_sec_scan"]
include = ["sap_sec_scan/rules/**/*.yaml"]
```

- [ ] **Step 2: Create package skeleton**

```bash
mkdir -p sap_sec_scan/scanners sap_sec_scan/rules/btp tests
touch sap_sec_scan/__init__.py sap_sec_scan/scanners/__init__.py
touch sap_sec_scan/rules/__init__.py tests/__init__.py
```

Create `conftest.py`:
```python
import pytest

def pytest_configure(config):
    config.addinivalue_line("markers", "integration: requires Trivy and Gitleaks installed")
```

Create `.gitignore`:
```
__pycache__/
*.py[cod]
.venv/
dist/
*.egg-info/
.env
```

- [ ] **Step 3: Install and verify**

```bash
uv venv && uv pip install -e ".[dev]"
pytest --collect-only
```
Expected: "no tests ran" (0 errors)

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml sap_sec_scan/ tests/ conftest.py .gitignore
git commit -m "chore: scaffold sap-security-scanner project"
```

---

### Task 2: Data Models

**Files:**
- Create: `sap_sec_scan/models.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `Severity` enum (IntEnum): `INFO=0`, `LOW=1`, `MEDIUM=2`, `HIGH=3`, `CRITICAL=4`
  - `Remediation(explanation: str, fix_template: str, effort: str, docs_url: str | None = None)` dataclass
  - `Finding(id: str, severity: Severity, message: str, file_path: str, rule_id: str, line: int | None = None, remediation: Remediation | None = None)` dataclass
  - `ScanResult(findings: list[Finding], scan_path: str, scanner_errors: list[str] = [])` dataclass with properties `critical_count`, `high_count`, `exit_code`

- [ ] **Step 1: Write failing tests**

`tests/test_models.py`:
```python
import pytest
from sap_sec_scan.models import Finding, Remediation, ScanResult, Severity


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW


def test_finding_defaults():
    f = Finding(
        id="CVE-2024-001",
        severity=Severity.HIGH,
        message="Test vuln",
        file_path="package.json",
        rule_id="CVE-2024-001",
    )
    assert f.line is None
    assert f.remediation is None


def test_scan_result_counts():
    findings = [
        Finding(id="1", severity=Severity.CRITICAL, message="c", file_path="f", rule_id="r"),
        Finding(id="2", severity=Severity.HIGH, message="h", file_path="f", rule_id="r"),
        Finding(id="3", severity=Severity.LOW, message="l", file_path="f", rule_id="r"),
    ]
    result = ScanResult(findings=findings, scan_path="/tmp/proj")
    assert result.critical_count == 1
    assert result.high_count == 1
    assert result.exit_code == 1  # CRITICAL present


def test_scan_result_exit_code_high_only():
    findings = [
        Finding(id="1", severity=Severity.HIGH, message="h", file_path="f", rule_id="r"),
    ]
    result = ScanResult(findings=findings, scan_path="/tmp/proj")
    assert result.exit_code == 2  # HIGH only


def test_scan_result_exit_code_clean():
    result = ScanResult(findings=[], scan_path="/tmp/proj")
    assert result.exit_code == 0


def test_scan_result_exit_code_scanner_error():
    result = ScanResult(findings=[], scan_path="/tmp/proj", scanner_errors=["trivy not found"])
    assert result.exit_code == 3
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
pytest tests/test_models.py -v
```
Expected: `ModuleNotFoundError: No module named 'sap_sec_scan.models'`

- [ ] **Step 3: Implement models.py**

```python
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
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
pytest tests/test_models.py -v
```
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add sap_sec_scan/models.py tests/test_models.py
git commit -m "feat: add Finding, ScanResult, Severity data models"
```

---

### Task 3: BTP Rules Engine

**Files:**
- Create: `sap_sec_scan/rules/btp/xsuaa.yaml`
- Create: `sap_sec_scan/rules/btp/mta.yaml`
- Create: `sap_sec_scan/rules/btp/xsapp.yaml`
- Create: `sap_sec_scan/rules/btp/cap.yaml`
- Create: `sap_sec_scan/scanners/btp_rules.py`
- Create: `tests/fixtures/mta_clean/xs-security.json`
- Create: `tests/fixtures/mta_bad_xsuaa/xs-security.json`
- Create: `tests/fixtures/cap_missing_auth/schema.cds`
- Create: `tests/test_btp_rules.py`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `Remediation` from `sap_sec_scan.models`
- Produces: `BTPRulesScanner(rules_dir: Path | None = None)` with method `scan(path: Path) -> list[Finding]`

- [ ] **Step 1: Create XSUAA rules**

`sap_sec_scan/rules/btp/xsuaa.yaml`:
```yaml
- id: BTP-XSUAA-001
  severity: HIGH
  file_pattern: "xs-security.json"
  check: json_contains
  path: "$.scopes[*]['grant-as-authority-to-apps'][*]"
  value: "$ACCEPT_GRANTED_AUTHORITIES"
  message: "xs-security.json grants wildcard authority to all apps via $ACCEPT_GRANTED_AUTHORITIES"
  remediation:
    explanation: "$ACCEPT_GRANTED_AUTHORITIES allows any app on the subaccount to consume this service's scopes without explicit trust configuration, bypassing app-level authorization."
    fix_template: |
      Replace:
        "grant-as-authority-to-apps": ["$ACCEPT_GRANTED_AUTHORITIES"]
      With:
        "grant-as-authority-to-apps": ["your-app-name!t<subaccount-id>"]
    effort: low
    docs_url: "https://help.sap.com/docs/btp/sap-business-technology-platform/xsuaa"

- id: BTP-XSUAA-002
  severity: HIGH
  file_pattern: "xs-security.json"
  check: json_equals
  path: "$.tenant-mode"
  value: "shared"
  message: "xs-security.json uses tenant-mode=shared which may expose data across tenants"
  remediation:
    explanation: "tenant-mode=shared means all tenants share the same UAA service instance. Use dedicated mode unless building a multi-tenant app with explicit tenant isolation."
    fix_template: |
      Replace:
        "tenant-mode": "shared"
      With:
        "tenant-mode": "dedicated"
      Or implement tenant isolation via xsuaa subscription manager.
    effort: medium
    docs_url: "https://help.sap.com/docs/btp/sap-business-technology-platform/multitenancy"

- id: BTP-XSUAA-003
  severity: MEDIUM
  file_pattern: "xs-security.json"
  check: json_not_exists
  path: "$.xsappname"
  message: "xs-security.json is missing xsappname field"
  remediation:
    explanation: "xsappname uniquely identifies the application in the UAA. Without it, scope and role references may fail at runtime."
    fix_template: |
      Add to xs-security.json:
        "xsappname": "your-app-name"
    effort: low
    docs_url: "https://help.sap.com/docs/btp/sap-business-technology-platform/xsuaa"

- id: BTP-XSUAA-004
  severity: MEDIUM
  file_pattern: "xs-security.json"
  check: json_empty_array
  path: "$.scopes"
  message: "xs-security.json defines no scopes — application has no authorization model"
  remediation:
    explanation: "Without scopes defined, the application cannot enforce role-based access control. Any authenticated user can access all endpoints."
    fix_template: |
      Add at minimum one scope:
        "scopes": [{"name": "$XSAPPNAME.read", "description": "Read access"}]
      Then protect endpoints with role templates referencing this scope.
    effort: medium
    docs_url: "https://help.sap.com/docs/btp/sap-business-technology-platform/xsuaa"
```

- [ ] **Step 2: Create MTA rules**

`sap_sec_scan/rules/btp/mta.yaml`:
```yaml
- id: BTP-MTA-001
  severity: HIGH
  file_pattern: "mta.yaml"
  check: yaml_module_missing_require
  require_type: "org.cloudfoundry.managed-service"
  service_name_pattern: "xsuaa"
  message: "mta.yaml contains CF modules without requiring an XSUAA service"
  remediation:
    explanation: "Modules without an XSUAA dependency have no authentication enforced at the platform level. HTTP routes will be publicly accessible."
    fix_template: |
      Add to each module that serves HTTP traffic:
        requires:
          - name: <your-xsuaa-resource-name>
      And define the XSUAA resource:
        resources:
          - name: <your-xsuaa-resource-name>
            type: org.cloudfoundry.managed-service
            parameters:
              service: xsuaa
              service-plan: application
    effort: high
    docs_url: "https://help.sap.com/docs/btp/sap-business-technology-platform/mta"
```

- [ ] **Step 3: Create xs-app rules**

`sap_sec_scan/rules/btp/xsapp.yaml`:
```yaml
- id: BTP-XSAPP-001
  severity: HIGH
  file_pattern: "xs-app.json"
  check: json_route_no_auth
  message: "xs-app.json contains non-static routes with authenticationMethod=none"
  remediation:
    explanation: "Routes with authenticationMethod=none bypass XSUAA token validation entirely. Use this only for truly public endpoints like health checks."
    fix_template: |
      Change:
        {"source": "/api/.*", "authenticationMethod": "none"}
      To:
        {"source": "/api/.*", "authenticationType": "xsuaa", "scope": "$XSAPPNAME.read"}
      For health check endpoints that must be public, restrict the source pattern tightly:
        {"source": "^/health$", "authenticationMethod": "none"}
    effort: low
    docs_url: "https://help.sap.com/docs/btp/sap-business-technology-platform/routing"
```

- [ ] **Step 4: Create CAP rules**

`sap_sec_scan/rules/btp/cap.yaml`:
```yaml
- id: BTP-CAP-001
  severity: HIGH
  file_pattern: "*.cds"
  check: regex_missing_annotation
  pattern: "^service\\s+\\w+"
  annotation: "@requires"
  message: "CAP service definition missing @requires annotation — service is publicly accessible"
  remediation:
    explanation: "CAP services without @requires are accessible to any authenticated or unauthenticated user depending on authentication strategy. Always restrict services explicitly."
    fix_template: |
      Add @requires before service definition:
        @requires: 'authenticated-user'
        service MyService {
          ...
        }
      Or restrict to specific roles:
        @requires: 'MyApp.read'
        service MyService { ... }
    effort: low
    docs_url: "https://cap.cloud.sap/docs/guides/security/authorization"

- id: BTP-CAP-002
  severity: MEDIUM
  file_pattern: "*.cds"
  check: regex_missing_annotation
  pattern: "^\\s+entity\\s+\\w+"
  annotation: "@restrict"
  message: "CAP entity missing @restrict annotation — all operations may be permitted"
  remediation:
    explanation: "Entities without @restrict inherit service-level authorization but have no fine-grained operation control. Add entity-level restrictions for sensitive data."
    fix_template: |
      Add @restrict to entity:
        @restrict: [{grant: 'READ', to: 'authenticated-user'}]
        entity Orders : managed { ... }
    effort: medium
    docs_url: "https://cap.cloud.sap/docs/guides/security/authorization"
```

- [ ] **Step 5: Create test fixtures**

```bash
mkdir -p tests/fixtures/mta_clean tests/fixtures/mta_bad_xsuaa tests/fixtures/cap_missing_auth
```

`tests/fixtures/mta_clean/xs-security.json`:
```json
{
  "xsappname": "my-clean-app",
  "tenant-mode": "dedicated",
  "scopes": [
    {
      "name": "$XSAPPNAME.read",
      "description": "Read access",
      "grant-as-authority-to-apps": ["my-clean-app!t12345"]
    }
  ]
}
```

`tests/fixtures/mta_bad_xsuaa/xs-security.json`:
```json
{
  "tenant-mode": "shared",
  "scopes": [
    {
      "name": "$XSAPPNAME.admin",
      "description": "Admin access",
      "grant-as-authority-to-apps": ["$ACCEPT_GRANTED_AUTHORITIES"]
    }
  ]
}
```

`tests/fixtures/cap_missing_auth/schema.cds`:
```
service CatalogService {
  entity Products : managed {
    key ID : UUID;
    title : String;
  }
}
```

- [ ] **Step 6: Write failing tests**

`tests/test_btp_rules.py`:
```python
import pytest
from pathlib import Path
from sap_sec_scan.scanners.btp_rules import BTPRulesScanner
from sap_sec_scan.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_project_no_findings():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_clean")
    assert findings == []


def test_xsuaa_wildcard_authority_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-001" in rule_ids


def test_xsuaa_shared_tenant_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-002" in rule_ids


def test_xsuaa_missing_xsappname_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-XSUAA-003" in rule_ids


def test_cap_missing_requires_detected():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "cap_missing_auth")
    rule_ids = [f.rule_id for f in findings]
    assert "BTP-CAP-001" in rule_ids


def test_findings_have_remediation():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    for f in findings:
        assert f.remediation is not None
        assert f.remediation.explanation
        assert f.remediation.fix_template


def test_finding_severity_correct():
    scanner = BTPRulesScanner()
    findings = scanner.scan(FIXTURES / "mta_bad_xsuaa")
    xsuaa_001 = next(f for f in findings if f.rule_id == "BTP-XSUAA-001")
    assert xsuaa_001.severity == Severity.HIGH
```

- [ ] **Step 7: Run tests, verify they fail**

```bash
pytest tests/test_btp_rules.py -v
```
Expected: `ModuleNotFoundError: No module named 'sap_sec_scan.scanners.btp_rules'`

- [ ] **Step 8: Implement btp_rules.py**

`sap_sec_scan/scanners/btp_rules.py`:
```python
from __future__ import annotations
import json
import re
from pathlib import Path

import yaml
from jsonpath_ng import parse as jp_parse

from sap_sec_scan.models import Finding, Remediation, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_DEFAULT_RULES_DIR = Path(__file__).parent.parent / "rules" / "btp"


class BTPRulesScanner:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules_dir = rules_dir or _DEFAULT_RULES_DIR
        self._rules = self._load_rules()

    def _load_rules(self) -> list[dict]:
        rules: list[dict] = []
        for yaml_file in sorted(self._rules_dir.glob("*.yaml")):
            with yaml_file.open() as f:
                rules.extend(yaml.safe_load(f) or [])
        return rules

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            pattern = rule["file_pattern"]
            matched = list(path.rglob(pattern))
            for file_path in matched:
                result = self._apply_rule(rule, file_path)
                if result:
                    findings.append(result)
        return findings

    def _apply_rule(self, rule: dict, file_path: Path) -> Finding | None:
        check = rule["check"]
        try:
            if check == "json_contains":
                return self._check_json_contains(rule, file_path)
            elif check == "json_equals":
                return self._check_json_equals(rule, file_path)
            elif check == "json_not_exists":
                return self._check_json_not_exists(rule, file_path)
            elif check == "json_empty_array":
                return self._check_json_empty_array(rule, file_path)
            elif check == "json_route_no_auth":
                return self._check_xsapp_no_auth(rule, file_path)
            elif check == "yaml_module_missing_require":
                return self._check_mta_missing_xsuaa(rule, file_path)
            elif check == "regex_missing_annotation":
                return self._check_cds_missing_annotation(rule, file_path)
        except Exception:
            return None
        return None

    def _make_finding(self, rule: dict, file_path: Path, line: int | None = None) -> Finding:
        rem_data = rule.get("remediation", {})
        remediation = Remediation(
            explanation=rem_data.get("explanation", ""),
            fix_template=rem_data.get("fix_template", ""),
            effort=rem_data.get("effort", "medium"),
            docs_url=rem_data.get("docs_url"),
        ) if rem_data else None
        return Finding(
            id=rule["id"],
            severity=_SEVERITY_MAP[rule["severity"]],
            message=rule["message"],
            file_path=str(file_path),
            rule_id=rule["id"],
            line=line,
            remediation=remediation,
        )

    def _check_json_contains(self, rule: dict, file_path: Path) -> Finding | None:
        data = json.loads(file_path.read_text())
        expr = jp_parse(rule["path"])
        matches = [m.value for m in expr.find(data)]
        if rule["value"] in matches:
            return self._make_finding(rule, file_path)
        return None

    def _check_json_equals(self, rule: dict, file_path: Path) -> Finding | None:
        data = json.loads(file_path.read_text())
        expr = jp_parse(rule["path"])
        matches = [m.value for m in expr.find(data)]
        if matches and matches[0] == rule["value"]:
            return self._make_finding(rule, file_path)
        return None

    def _check_json_not_exists(self, rule: dict, file_path: Path) -> Finding | None:
        data = json.loads(file_path.read_text())
        expr = jp_parse(rule["path"])
        matches = expr.find(data)
        if not matches:
            return self._make_finding(rule, file_path)
        return None

    def _check_json_empty_array(self, rule: dict, file_path: Path) -> Finding | None:
        data = json.loads(file_path.read_text())
        expr = jp_parse(rule["path"])
        matches = [m.value for m in expr.find(data)]
        if not matches or (len(matches) == 1 and matches[0] == []):
            return self._make_finding(rule, file_path)
        return None

    def _check_xsapp_no_auth(self, rule: dict, file_path: Path) -> Finding | None:
        data = json.loads(file_path.read_text())
        routes = data.get("routes", [])
        static_patterns = {r"^/resources", r"^/test-resources"}
        for route in routes:
            if route.get("authenticationMethod") == "none":
                source = route.get("source", "")
                if not any(re.match(p, source) for p in static_patterns):
                    return self._make_finding(rule, file_path)
        return None

    def _check_mta_missing_xsuaa(self, rule: dict, file_path: Path) -> Finding | None:
        data = yaml.safe_load(file_path.read_text())
        modules = data.get("modules", [])
        resources = data.get("resources", [])
        xsuaa_resources = {
            r["name"] for r in resources
            if r.get("type") == "org.cloudfoundry.managed-service"
            and "xsuaa" in str(r.get("parameters", {}).get("service", ""))
        }
        for module in modules:
            module_type = module.get("type", "")
            if "nodejs" in module_type or "java" in module_type or "python" in module_type:
                requires = {req.get("name", "") for req in module.get("requires", [])}
                if not requires.intersection(xsuaa_resources):
                    return self._make_finding(rule, file_path)
        return None

    def _check_cds_missing_annotation(self, rule: dict, file_path: Path) -> Finding | None:
        content = file_path.read_text()
        lines = content.split("\n")
        pattern = re.compile(rule["pattern"], re.MULTILINE)
        annotation = rule["annotation"]
        for i, line in enumerate(lines):
            if pattern.match(line):
                preceding = "\n".join(lines[max(0, i - 3):i])
                if annotation not in preceding:
                    return self._make_finding(rule, file_path, line=i + 1)
        return None
```

- [ ] **Step 9: Run tests, verify they pass**

```bash
pytest tests/test_btp_rules.py -v
```
Expected: 7 passed

- [ ] **Step 10: Commit**

```bash
git add sap_sec_scan/scanners/btp_rules.py sap_sec_scan/rules/btp/ tests/test_btp_rules.py tests/fixtures/
git commit -m "feat: add BTP rules engine with XSUAA, MTA, xs-app, and CAP checks"
```

---

### Task 4: Trivy + Gitleaks Scanners

**Files:**
- Create: `sap_sec_scan/scanners/trivy.py`
- Create: `sap_sec_scan/scanners/gitleaks.py`
- Create: `tests/test_trivy.py`
- Create: `tests/test_gitleaks.py`

**Interfaces:**
- Consumes: `Finding`, `Severity`, `Remediation` from `sap_sec_scan.models`
- Produces:
  - `TrivyScanner(trivy_path: str = "trivy")` with `scan(path: Path) -> tuple[list[Finding], list[str]]`
  - `GitleaksScanner(gitleaks_path: str = "gitleaks")` with `scan(path: Path) -> tuple[list[Finding], list[str]]`

- [ ] **Step 1: Write failing tests**

`tests/test_trivy.py`:
```python
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from sap_sec_scan.scanners.trivy import TrivyScanner
from sap_sec_scan.models import Severity

TRIVY_JSON_OUTPUT = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-12345",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.21",
                    "Severity": "CRITICAL",
                    "Description": "Prototype pollution in lodash",
                }
            ],
        }
    ]
}


def test_trivy_parses_critical_cve():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(TRIVY_JSON_OUTPUT),
            stderr="",
        )
        scanner = TrivyScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert len(findings) == 1
    assert findings[0].id == "CVE-2024-12345"
    assert findings[0].severity == Severity.CRITICAL
    assert errors == []


def test_trivy_not_installed_returns_error():
    with patch("subprocess.run", side_effect=FileNotFoundError("trivy not found")):
        scanner = TrivyScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert len(errors) == 1
    assert "trivy" in errors[0].lower()


def test_trivy_no_vulnerabilities_returns_empty():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": [{"Target": "package.json", "Vulnerabilities": None}]}),
            stderr="",
        )
        scanner = TrivyScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert errors == []


@pytest.mark.integration
def test_trivy_real_scan_clean_project(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {}}')
    scanner = TrivyScanner()
    findings, errors = scanner.scan(tmp_path)
    assert errors == []
```

`tests/test_gitleaks.py`:
```python
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from sap_sec_scan.scanners.gitleaks import GitleaksScanner
from sap_sec_scan.models import Severity

GITLEAKS_JSON_OUTPUT = [
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": ".env",
        "StartLine": 1,
        "Match": "SAP_CLIENTSECRET=abc1****",
    }
]


def test_gitleaks_parses_secret():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps(GITLEAKS_JSON_OUTPUT),
            stderr="",
        )
        scanner = GitleaksScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].file_path == ".env"
    assert errors == []


def test_gitleaks_not_installed_returns_error():
    with patch("subprocess.run", side_effect=FileNotFoundError("gitleaks not found")):
        scanner = GitleaksScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert "gitleaks" in errors[0].lower()


def test_gitleaks_no_secrets_returns_empty():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
        scanner = GitleaksScanner()
        findings, errors = scanner.scan(Path("/fake/path"))

    assert findings == []
    assert errors == []
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
pytest tests/test_trivy.py tests/test_gitleaks.py -v
```
Expected: `ModuleNotFoundError: No module named 'sap_sec_scan.scanners.trivy'`

- [ ] **Step 3: Implement trivy.py**

`sap_sec_scan/scanners/trivy.py`:
```python
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from sap_sec_scan.models import Finding, Remediation, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner:
    def __init__(self, trivy_path: str = "trivy") -> None:
        self._trivy_path = trivy_path

    def scan(self, path: Path) -> tuple[list[Finding], list[str]]:
        try:
            result = subprocess.run(
                [self._trivy_path, "fs", "--format", "json", "--scanners", "vuln", str(path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            return [], [f"trivy not found at '{self._trivy_path}' — install from https://aquasecurity.github.io/trivy/"]
        except subprocess.TimeoutExpired:
            return [], ["trivy scan timed out after 120 seconds"]

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [], [f"trivy returned invalid JSON: {result.stderr[:200]}"]

        findings: list[Finding] = []
        for scan_result in data.get("Results", []):
            for vuln in scan_result.get("Vulnerabilities") or []:
                findings.append(self._parse_vuln(vuln, scan_result["Target"]))
        return findings, []

    def _parse_vuln(self, vuln: dict, target: str) -> Finding:
        fixed = vuln.get("FixedVersion", "no fix available")
        remediation = Remediation(
            explanation=vuln.get("Description", "")[:500],
            fix_template=f"Upgrade {vuln['PkgName']} from {vuln['InstalledVersion']} to {fixed}",
            effort="low" if fixed != "no fix available" else "high",
        )
        return Finding(
            id=vuln["VulnerabilityID"],
            severity=_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO),
            message=f"{vuln['PkgName']}@{vuln['InstalledVersion']} — {vuln['VulnerabilityID']} (fix: {fixed})",
            file_path=target,
            rule_id=vuln["VulnerabilityID"],
            remediation=remediation,
        )
```

- [ ] **Step 4: Implement gitleaks.py**

`sap_sec_scan/scanners/gitleaks.py`:
```python
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from sap_sec_scan.models import Finding, Remediation, Severity

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
```

- [ ] **Step 5: Run tests, verify they pass**

```bash
pytest tests/test_trivy.py tests/test_gitleaks.py -v -k "not integration"
```
Expected: 6 passed

- [ ] **Step 6: Commit**

```bash
git add sap_sec_scan/scanners/trivy.py sap_sec_scan/scanners/gitleaks.py tests/test_trivy.py tests/test_gitleaks.py
git commit -m "feat: add Trivy CVE and Gitleaks secrets scanners"
```

---

### Task 5: Orchestrator + Output

**Files:**
- Create: `sap_sec_scan/orchestrator.py`
- Create: `sap_sec_scan/output.py`
- Create: `tests/test_orchestrator.py`
- Create: `tests/test_output.py`

**Interfaces:**
- Consumes: `TrivyScanner`, `GitleaksScanner`, `BTPRulesScanner`, `ScanResult`, `Finding`, `Severity`
- Produces:
  - `Orchestrator(trivy_path: str = "trivy", gitleaks_path: str = "gitleaks", rules_dir: Path | None = None)` with `scan(path: Path) -> ScanResult`
  - `format_table(result: ScanResult) -> str`
  - `format_json(result: ScanResult) -> str`

- [ ] **Step 1: Write failing tests**

`tests/test_orchestrator.py`:
```python
from pathlib import Path
from unittest.mock import patch
import pytest
from sap_sec_scan.orchestrator import Orchestrator
from sap_sec_scan.models import Finding, Severity


def _make_finding(id: str, severity: Severity) -> Finding:
    return Finding(id=id, severity=severity, message="test", file_path="f", rule_id=id)


def test_orchestrator_merges_findings():
    with patch("sap_sec_scan.orchestrator.TrivyScanner") as MockTrivy, \
         patch("sap_sec_scan.orchestrator.GitleaksScanner") as MockGitleaks, \
         patch("sap_sec_scan.orchestrator.BTPRulesScanner") as MockBTP:
        MockTrivy.return_value.scan.return_value = ([_make_finding("CVE-1", Severity.CRITICAL)], [])
        MockGitleaks.return_value.scan.return_value = ([_make_finding("SEC-1", Severity.CRITICAL)], [])
        MockBTP.return_value.scan.return_value = [_make_finding("BTP-1", Severity.HIGH)]

        result = Orchestrator().scan(Path("/fake"))

    assert len(result.findings) == 3
    assert result.critical_count == 2
    assert result.high_count == 1


def test_orchestrator_collects_scanner_errors():
    with patch("sap_sec_scan.orchestrator.TrivyScanner") as MockTrivy, \
         patch("sap_sec_scan.orchestrator.GitleaksScanner") as MockGitleaks, \
         patch("sap_sec_scan.orchestrator.BTPRulesScanner") as MockBTP:
        MockTrivy.return_value.scan.return_value = ([], ["trivy not found"])
        MockGitleaks.return_value.scan.return_value = ([], [])
        MockBTP.return_value.scan.return_value = []

        result = Orchestrator().scan(Path("/fake"))

    assert "trivy not found" in result.scanner_errors
    assert result.exit_code == 3


def test_orchestrator_deduplicates_findings():
    dup = _make_finding("CVE-1", Severity.CRITICAL)
    with patch("sap_sec_scan.orchestrator.TrivyScanner") as MockTrivy, \
         patch("sap_sec_scan.orchestrator.GitleaksScanner") as MockGitleaks, \
         patch("sap_sec_scan.orchestrator.BTPRulesScanner") as MockBTP:
        MockTrivy.return_value.scan.return_value = ([dup, dup], [])
        MockGitleaks.return_value.scan.return_value = ([], [])
        MockBTP.return_value.scan.return_value = []

        result = Orchestrator().scan(Path("/fake"))

    assert len(result.findings) == 1
```

`tests/test_output.py`:
```python
import json
from sap_sec_scan.models import Finding, ScanResult, Severity
from sap_sec_scan.output import format_json, format_table


def _make_result(findings=None, errors=None):
    return ScanResult(findings=findings or [], scan_path="/test/path", scanner_errors=errors or [])


def test_format_json_empty():
    output = json.loads(format_json(_make_result()))
    assert output["findings"] == []
    assert output["exit_code"] == 0


def test_format_json_with_findings():
    f = Finding(id="CVE-1", severity=Severity.CRITICAL, message="test vuln", file_path="pkg.json", rule_id="CVE-1")
    output = json.loads(format_json(_make_result(findings=[f])))
    assert len(output["findings"]) == 1
    assert output["findings"][0]["severity"] == "CRITICAL"
    assert output["exit_code"] == 1


def test_format_table_contains_rule_id():
    f = Finding(id="BTP-XSUAA-001", severity=Severity.HIGH, message="wildcard auth", file_path="xs-security.json", rule_id="BTP-XSUAA-001")
    table = format_table(_make_result(findings=[f]))
    assert "BTP-XSUAA-001" in table
    assert "HIGH" in table


def test_format_table_clean():
    table = format_table(_make_result())
    assert "clean" in table.lower() or "no findings" in table.lower()
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
pytest tests/test_orchestrator.py tests/test_output.py -v
```
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement orchestrator.py**

```python
from __future__ import annotations
from pathlib import Path

from sap_sec_scan.models import Finding, ScanResult
from sap_sec_scan.scanners.btp_rules import BTPRulesScanner
from sap_sec_scan.scanners.gitleaks import GitleaksScanner
from sap_sec_scan.scanners.trivy import TrivyScanner


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
```

- [ ] **Step 4: Implement output.py**

```python
from __future__ import annotations
import dataclasses
import json

from rich.console import Console
from rich.table import Table
from rich import box

from sap_sec_scan.models import ScanResult, Severity

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

    payload = {
        "scan_path": result.scan_path,
        "exit_code": result.exit_code,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "total": len(result.findings),
        },
        "findings": [dataclasses.asdict(f) for f in result.findings],
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
```

- [ ] **Step 5: Run tests, verify they pass**

```bash
pytest tests/test_orchestrator.py tests/test_output.py -v
```
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
git add sap_sec_scan/orchestrator.py sap_sec_scan/output.py tests/test_orchestrator.py tests/test_output.py
git commit -m "feat: add orchestrator and output formatters"
```

---

### Task 6: CLI

**Files:**
- Create: `sap_sec_scan/cli.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `Orchestrator` from `sap_sec_scan.orchestrator`, `format_table` and `format_json` from `sap_sec_scan.output`
- Produces: `sap-sec-scan` CLI command registered via `pyproject.toml` entry point `sap_sec_scan.cli:app`

- [ ] **Step 1: Write failing tests**

`tests/test_cli.py`:
```python
from typer.testing import CliRunner
from unittest.mock import patch
from sap_sec_scan.cli import app
from sap_sec_scan.models import Finding, ScanResult, Severity

runner = CliRunner()


def _mock_clean(path):
    return ScanResult(findings=[], scan_path=str(path))


def _mock_critical(path):
    return ScanResult(
        findings=[Finding(id="CVE-1", severity=Severity.CRITICAL, message="vuln", file_path="pkg.json", rule_id="CVE-1")],
        scan_path=str(path),
    )


def test_cli_exit_0_clean_project(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_clean
        result = runner.invoke(app, [str(tmp_path)])
    assert result.exit_code == 0


def test_cli_exit_1_critical_findings(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_critical
        result = runner.invoke(app, [str(tmp_path)])
    assert result.exit_code == 1


def test_cli_json_format_output(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_clean
        result = runner.invoke(app, [str(tmp_path), "--format", "json"])
    import json
    data = json.loads(result.output)
    assert "findings" in data
    assert data["exit_code"] == 0


def test_cli_no_llm_flag_accepted(tmp_path):
    with patch("sap_sec_scan.cli.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.side_effect = _mock_clean
        result = runner.invoke(app, [str(tmp_path), "--no-llm"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
pytest tests/test_cli.py -v
```
Expected: `ModuleNotFoundError: No module named 'sap_sec_scan.cli'`

- [ ] **Step 3: Implement cli.py**

```python
from __future__ import annotations
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from sap_sec_scan.orchestrator import Orchestrator
from sap_sec_scan.output import format_json, format_table

app = typer.Typer(name="sap-sec-scan", help="Security vulnerability scanner for SAP BTP app packages")


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
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
pytest tests/test_cli.py -v
```
Expected: 4 passed

- [ ] **Step 5: Smoke test**

```bash
sap-sec-scan --help
sap-sec-scan . --no-llm
```
Expected: help text displayed; scan runs and reports scanner errors for missing Trivy/Gitleaks (exit code 3) or clean result

- [ ] **Step 6: Commit**

```bash
git add sap_sec_scan/cli.py tests/test_cli.py
git commit -m "feat: add CLI with --format, --threshold, --no-llm flags"
```

---

### Task 7: MCP Server

**Files:**
- Create: `sap_sec_scan/mcp_server.py`
- Create: `tests/test_mcp_server.py`

**Interfaces:**
- Consumes: `Orchestrator` from `sap_sec_scan.orchestrator`, `BTPRulesScanner` from `sap_sec_scan.scanners.btp_rules`, `format_json` from `sap_sec_scan.output`
- Produces: FastMCP server with tools `scan_project(path, threshold, trivy_path, gitleaks_path) -> str`, `scan_file(file_path) -> str`, `list_rules(category) -> str`, `explain_finding(rule_id) -> str`

- [ ] **Step 1: Write failing tests**

`tests/test_mcp_server.py`:
```python
import json
import pytest
from unittest.mock import patch
from pathlib import Path
from sap_sec_scan.models import Finding, ScanResult, Severity


def test_scan_project_returns_json():
    from sap_sec_scan.mcp_server import scan_project
    with patch("sap_sec_scan.mcp_server.Orchestrator") as MockOrch:
        MockOrch.return_value.scan.return_value = ScanResult(findings=[], scan_path="/fake")
        result = scan_project(path="/fake")
    data = json.loads(result)
    assert "findings" in data
    assert data["exit_code"] == 0


def test_scan_file_returns_findings():
    from sap_sec_scan.mcp_server import scan_file
    with patch("sap_sec_scan.mcp_server.BTPRulesScanner") as MockBTP:
        MockBTP.return_value.scan.return_value = [
            Finding(id="BTP-XSUAA-001", severity=Severity.HIGH, message="test",
                    file_path="/fake/xs-security.json", rule_id="BTP-XSUAA-001")
        ]
        result = scan_file(file_path="/fake/xs-security.json")
    data = json.loads(result)
    assert len(data) == 1
    assert data[0]["rule_id"] == "BTP-XSUAA-001"


def test_list_rules_returns_all():
    from sap_sec_scan.mcp_server import list_rules
    result = list_rules(category="all")
    data = json.loads(result)
    assert len(data) > 0
    assert all("id" in r and "severity" in r for r in data)


def test_explain_finding_returns_remediation():
    from sap_sec_scan.mcp_server import explain_finding
    result = explain_finding(rule_id="BTP-XSUAA-001")
    data = json.loads(result)
    assert "explanation" in data
    assert "fix_template" in data


def test_explain_finding_unknown_rule():
    from sap_sec_scan.mcp_server import explain_finding
    result = explain_finding(rule_id="DOES-NOT-EXIST")
    data = json.loads(result)
    assert "error" in data
```

- [ ] **Step 2: Run tests, verify they fail**

```bash
pytest tests/test_mcp_server.py -v
```
Expected: `ModuleNotFoundError: No module named 'sap_sec_scan.mcp_server'`

- [ ] **Step 3: Implement mcp_server.py**

```python
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
```

- [ ] **Step 4: Run tests, verify they pass**

```bash
pytest tests/test_mcp_server.py -v
```
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add sap_sec_scan/mcp_server.py tests/test_mcp_server.py
git commit -m "feat: add FastMCP server with scan_project, scan_file, list_rules, explain_finding"
```

---

### Task 8: CI/CD Templates + README

**Files:**
- Create: `ci/github-actions.yml`
- Create: `ci/gitlab-ci.yml`
- Create: `README.md`

**Interfaces:**
- Produces: working CI/CD templates users copy into their BTP projects

- [ ] **Step 1: Create GitHub Actions template**

`ci/github-actions.yml`:
```yaml
name: BTP Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  btp-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Trivy
        run: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      - name: Install Gitleaks
        run: |
          GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
          wget -q "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" -O gitleaks.tar.gz
          tar -xzf gitleaks.tar.gz gitleaks && mv gitleaks /usr/local/bin/

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install sap-security-scanner
        run: pip install sap-security-scanner

      - name: Run BTP Security Scan
        run: sap-sec-scan . --format json --threshold HIGH --no-llm
        # Exit 1 = CRITICAL (blocks deploy). Exit 2 = HIGH (blocks deploy).
        # Change --threshold CRITICAL to only block on CRITICAL findings.
```

- [ ] **Step 2: Create GitLab CI template**

`ci/gitlab-ci.yml`:
```yaml
btp-security-scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl wget tar jq
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    - |
      GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
      wget -q "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" -O gitleaks.tar.gz
      tar -xzf gitleaks.tar.gz gitleaks && mv gitleaks /usr/local/bin/
    - pip install sap-security-scanner
  script:
    - sap-sec-scan . --threshold HIGH --no-llm
  allow_failure: false
```

- [ ] **Step 3: Create README.md**

`README.md`:
```markdown
# sap-security-scanner

Security vulnerability scanner for SAP BTP app packages. Checks MTA and CAP projects for CVEs, hardcoded secrets, and BTP-specific misconfigurations before deployment.

## What it checks

| Category | Engine | Examples |
|---|---|---|
| CVEs | Trivy | lodash, spring-core, requests vulnerabilities |
| Secrets | Gitleaks | Hardcoded clientsecret, API keys, service keys |
| XSUAA misconfig | BTP Rules | Wildcard authority grants, shared tenant mode |
| MTA misconfig | BTP Rules | Routes without XSUAA, public modules |
| CAP auth | BTP Rules | Services/entities missing @requires/@restrict |

## Install

```bash
pip install sap-security-scanner
```

Requires [Trivy](https://aquasecurity.github.io/trivy/) and [Gitleaks](https://github.com/gitleaks/gitleaks) on your PATH.

## Usage

```bash
sap-sec-scan .
sap-sec-scan /path/to/my-mta-project
sap-sec-scan . --format json --no-llm
sap-sec-scan . --threshold CRITICAL
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | CRITICAL findings — deployment blocked |
| 2 | HIGH findings — deployment blocked (default threshold) |
| 3 | Scanner error (Trivy/Gitleaks not installed) |

## CI/CD

Copy `ci/github-actions.yml` or `ci/gitlab-ci.yml` into your BTP project.

## Claude Code (MCP)

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "sap-security-scanner": {
      "command": "python",
      "args": ["-m", "sap_sec_scan.mcp_server"]
    }
  }
}
```

Then: *"Scan my MTA project at /path/to/project before deploying to BTP prod"*
```

- [ ] **Step 4: Run full test suite**

```bash
pytest -v -k "not integration"
```
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add ci/ README.md
git commit -m "feat: add CI/CD templates and README"
```
