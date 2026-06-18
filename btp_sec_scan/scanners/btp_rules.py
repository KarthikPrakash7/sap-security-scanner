from __future__ import annotations
import json
import re
from pathlib import Path

import yaml
from jsonpath_ng import parse as jp_parse

from btp_sec_scan.models import Finding, Remediation, Severity

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
