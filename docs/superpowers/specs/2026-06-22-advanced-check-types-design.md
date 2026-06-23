# Advanced Check Types: json_greater_than & yaml_env_credentials

## Summary

Add two new check types to `BTPRulesScanner` enabling rules that existing check types cannot express: numeric threshold comparisons and env var credential leak detection.

## Motivation

Current check types (`json_contains`, `json_equals`, `json_not_exists`, etc.) cover presence/equality but not:
- Numeric comparisons (e.g., token validity > 12h)
- Env var scanning for hardcoded secrets in `mta.yaml` modules

Both are high-value SAP BTP security checks with no workaround in the current rule DSL.

## Design

### Approach

Add two new handler methods to `BTPRulesScanner._apply_rule` in `sap_sec_scan/scanners/btp_rules.py`, following the existing `elif` dispatch pattern. No structural changes.

### Check Type 1: `json_greater_than`

Fires when a JSON path value exceeds a numeric threshold.

**YAML rule fields:**
- `path` — jsonpath expression
- `threshold` — int or float; finding raised if matched value > threshold

**Example rule:**
```yaml
- id: BTP-XSUAA-006
  severity: MEDIUM
  file_pattern: "xs-security.json"
  check: json_greater_than
  path: "$.oauth2-configuration.token-validity"
  threshold: 43200
  message: "xs-security.json sets token-validity > 12h — long-lived tokens increase breach window"
```

**Logic:** Extract value at `path`. If value exists and `value > threshold`, emit finding.

### Check Type 2: `yaml_env_credentials`

Fires when an `mta.yaml` module env var key matches a sensitive pattern AND the value doesn't look like a placeholder.

**YAML rule fields:**
- `key_patterns` — list of regex strings matched against env var key names (case-insensitive recommended via `(?i)`)
- `skip_value_patterns` — list of regex strings; if value matches any, skip (not a hardcoded credential)

**Example skip patterns:**
- `^~\{` — MTA variable reference (`~{xsuaa-credentials/clientsecret}`)
- `^\$\{` — CF environment variable substitution
- `^\(\(` — Concourse/CredHub secret reference

**Example rule:**
```yaml
- id: BTP-MTA-002
  severity: HIGH
  file_pattern: "mta.yaml"
  check: yaml_env_credentials
  key_patterns:
    - "(?i)(password|secret|clientsecret|apikey|api_key|token|credential)"
  skip_value_patterns:
    - "^~\\{"
    - "^\\$\\{"
    - "^\\(\\("
  message: "mta.yaml contains a hardcoded credential in module env vars"
```

**Logic:** For each module, iterate `properties` (env vars). For each key matching any `key_patterns`, check if value matches any `skip_value_patterns`. If not — hardcoded credential, emit finding.

## Files Changed

| File | Change |
|---|---|
| `sap_sec_scan/scanners/btp_rules.py` | Add `_check_json_greater_than` and `_check_yaml_env_credentials` methods; wire into `_apply_rule` |
| `sap_sec_scan/rules/btp/xsuaa.yaml` | Add BTP-XSUAA-006 (token validity) |
| `sap_sec_scan/rules/btp/mta.yaml` | Add BTP-MTA-002 (env var credentials) |
| `tests/fixtures/mta_bad_xsuaa/xs-security.json` | Add `oauth2-configuration.token-validity` to trigger BTP-XSUAA-006 |
| `tests/fixtures/mta_clean/xs-security.json` | Add valid `oauth2-configuration.token-validity` ≤ 43200 |
| `tests/fixtures/mta_bad_env/mta.yaml` | New fixture with hardcoded credential in env vars |
| `tests/fixtures/mta_clean/mta.yaml` | New clean MTA fixture with MTA variable references |
| `tests/test_btp_rules.py` | Tests for both new check types |

## Error Handling

- `json_greater_than`: if path not found or value not numeric, return `None` (no finding, no crash).
- `yaml_env_credentials`: if `properties` missing or not a dict, skip module silently.

## Testing

- `test_json_greater_than_detected` — fixture with `token-validity: 86400` (24h) triggers BTP-XSUAA-006
- `test_json_greater_than_not_triggered` — fixture with `token-validity: 3600` (1h) does not trigger
- `test_yaml_env_credentials_detected` — fixture with `PASSWORD: actual-secret` triggers BTP-MTA-002
- `test_yaml_env_credentials_skips_mta_ref` — fixture with `PASSWORD: ~{xsuaa/password}` does not trigger
- Clean fixture `test_clean_project_no_findings` continues to pass
