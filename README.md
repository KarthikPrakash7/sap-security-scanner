# btp-security-scanner

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
pip install btp-security-scanner
```

Requires [Trivy](https://aquasecurity.github.io/trivy/) and [Gitleaks](https://github.com/gitleaks/gitleaks) on your PATH.

## Usage

```bash
btp-sec-scan .
btp-sec-scan /path/to/my-mta-project
btp-sec-scan . --format json --no-llm
btp-sec-scan . --threshold CRITICAL
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
    "btp-security-scanner": {
      "command": "python",
      "args": ["-m", "btp_sec_scan.mcp_server"]
    }
  }
}
```

Then: *"Scan my MTA project at /path/to/project before deploying to BTP prod"*
