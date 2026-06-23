# sap-security-scanner

Security vulnerability scanner for SAP BTP app packages. Checks MTA and CAP projects for CVEs, hardcoded secrets, and BTP-specific misconfigurations before deployment.

## What it checks

| Category | Engine | Examples |
|---|---|---|
| CVEs | Trivy | lodash, spring-core, requests vulnerabilities |
| CVEs + reachability (opt-in) | OWASP dep-scan | Reachability-aware SCA across npm/maven/pip/go, CycloneDX VDR |
| Secrets | Gitleaks | Hardcoded clientsecret, API keys, service keys |
| XSUAA misconfig | BTP Rules | Wildcard authority grants, shared tenant mode, wildcard foreign-scope-references |
| MTA misconfig | BTP Rules | Routes without XSUAA, public modules, hardcoded env credentials |
| AppRouter misconfig | BTP Rules | CORS wildcard, disabled CSRF protection, plaintext http:// routes |
| Destination misconfig | BTP Rules | NoAuthentication or http:// destinations in mta.yaml |
| CAP auth | BTP Rules | Services/entities missing @requires/@restrict |

## Install

```bash
pip install sap-security-scanner
```

Requires [Trivy](https://aquasecurity.github.io/trivy/) and [Gitleaks](https://github.com/gitleaks/gitleaks) on your PATH.

Optional: install [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan) (`pip install owasp-depscan`) to enable the reachability-aware `--depscan` engine. It runs alongside Trivy, not instead of it.

dep-scan builds an SBOM via [cdxgen](https://github.com/CycloneDX/cdxgen), so it needs **either Docker** (default engine) **or a local cdxgen** (`npm install -g @cyclonedx/cdxgen`) on PATH. On first run it downloads a vulnerability database (~1 GB). If neither cdxgen nor Docker is available, no SBOM is produced and `--depscan` reports a scanner error rather than a false "clean".

## Usage

```bash
sap-sec-scan .
sap-sec-scan /path/to/my-mta-project
sap-sec-scan . --format json --no-llm
sap-sec-scan . --format sarif > results.sarif
sap-sec-scan . --threshold CRITICAL
sap-sec-scan . --depscan          # also run OWASP dep-scan (reachability + SBOM)
```

Formats: `table` (default), `json`, `sarif` (SARIF 2.1.0 for GitHub code scanning).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | CRITICAL findings — deployment blocked |
| 2 | HIGH findings — deployment blocked (default threshold) |
| 3 | Scanner error (Trivy/Gitleaks not installed) |

## CI/CD

Copy `ci/github-actions.yml` or `ci/gitlab-ci.yml` into your BTP project. The GitHub
workflow uploads a SARIF report to the repo's code scanning tab, so findings show up
as inline PR annotations.

## pre-commit

Add to `.pre-commit-config.yaml` to block commits with HIGH+ findings:

```yaml
repos:
  - repo: https://github.com/KarthikPrakash7/sap-security-scanner
    rev: v0.1.0
    hooks:
      - id: sap-sec-scan
```

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
