# Secret Scan 360

A comprehensive secret scanning solution that provides end-to-end detection, validation, risk assessment, and automated remediation of exposed secrets.

## 🚀 Quick Start

```bash
# Install SS360
pip install -e .

# Basic scan
ss360 scan . --policy policy.example.yml

# Generate autofix plan
ss360 scan . --policy policy.demo.yml --autofix plan

# Output SARIF for CI
ss360 scan . --format sarif --sarif-out results.sarif
```

## 🔍 Features

### **End-to-End Secret Detection Pipeline**
- **Detect**: GitHub PAT, AWS Access Keys, and extensible detector system
- **Validate**: Live network validation with CI-safe fallbacks  
- **Risk Assessment**: Context-aware scoring (0-100) based on location, validation, exposure
- **Autofix**: Automated secret replacement and rotation with safety checks
- **Policy Enforcement**: Configurable budgets, thresholds, and time-bound waivers
- **Multiple Formats**: Text, JSON, SARIF output for CI integration

### **Built-in Detectors**
- **GitHub Personal Access Tokens**: `ghp_*`, `github_pat_*`, `ghs_*`, `gho_*`
- **AWS Access Keys**: `AKIA*` access key IDs and secret access keys
- [Slack Webhook Detector](detectors/slack_webhook.py) — detects Slack incoming webhook URLs

### **Risk Scoring System**
Deterministic 0-100 risk scoring based on:
- **Base Severity**: Type-specific base scores (GitHub PAT: 70, AWS: 80)
- **Validation State**: Confirmed valid (↑30%), invalid (↓60%), indeterminate (↓10%)
- **Path Context**: Production paths (↑20%), test paths (↓30%), docs (↓70%)
- **Repository Exposure**: Public repos (↑20%), external contributors (↑10%)
- **Historical Age**: Long-lived secrets (↑20% if >1 year)

### **Autofix & Rotation**
Safe automated remediation with:
- **GitHub PAT**: Replace with `${{ secrets.GITHUB_TOKEN }}` + revoke via API
- **AWS Keys**: Replace with Secrets Manager refs + deactivate via IAM
- **Pull Request Creation**: Automated PRs with remediation checklists
- **Safety Checks**: Dry-run mode, explicit confirmation flags, reversibility tracking

## 📋 Policy Configuration

Create a `policy.yml` file:

```yaml
version: 1
validators:
  allow_network: false  # Safe for CI - skips network validators  
  global_qps: 2.0       # Global rate limit (queries per second)

budgets:
  new_findings: 0       # Fail if any new findings (strict mode)
  max_risk_score: 40    # Fail if any finding exceeds this risk score

autofix:
  min_risk_score: 60    # Only autofix findings with risk >= 60
  require_confirmation: true  # Require --i-know-what-im-doing flag

waivers:  # Temporary exceptions with expiry
  - rule: "github_pat"
    path: "tests/**/*"
    expiry: "2024-12-31T23:59:59"
    reason: "Test fixtures contain fake tokens"
```

## 🛠️ Command Line Interface

### Basic Scanning
```bash
# Scan current directory with policy
ss360 scan . --policy policy.yml

# Scan specific directory
ss360 scan src/ --policy my-policy.yml

# Different output formats
ss360 scan . --format json --json-out results.json
ss360 scan . --format sarif --sarif-out results.sarif
```

### Autofix Operations
```bash
# Generate autofix plan (safe, read-only)
ss360 scan . --autofix plan

# Apply fixes (requires confirmation)
ss360 scan . --autofix apply --i-know-what-im-doing
```

### Policy Enforcement Examples
```bash
# Strict policy (fail on any findings)
ss360 scan . --policy policy.example.yml

# Permissive policy (allow some findings)
ss360 scan . --policy policy.demo.yml
```

## 🔬 Validation System

SS360 includes a pluggable validation system that can verify candidate findings while maintaining strict network guardrails suitable for CI environments.

### Key Features

- **Network Kill-Switch**: Validators requiring network access are automatically skipped when `allow_network: false` (default)
- **Rate Limiting**: Built-in token bucket algorithm prevents validator abuse with configurable QPS limits
- **Secret Redaction**: All validator evidence is automatically redacted to show only the last 4 characters of sensitive values
- **Pluggable Architecture**: Easy to add new validators following the `Validator` protocol

### Built-in Validators

#### Local Validators (No Network Required)
- **Slack Webhook Format Validator**: Validates Slack webhook URL format (original, basic format check)
- **Slack Webhook Local Validator**: Enhanced local Slack webhook validation with component validation (team ID, channel ID, token format)

#### Network Validators (Require `allow_network: true`)
- **GitHub PAT Live Validator**: Validates GitHub tokens via API (`/user` endpoint)
- **AWS Access Key Live Validator**: Validates AWS keys via STS (format validation + future STS integration)
- **GCP Service Account Key Live Validator**: Validates GCP service account keys via IAM Credentials API (`generateAccessToken`)
- **Azure SAS Live Validator**: Validates Azure SAS tokens via HEAD request to test accessibility

> **⚠️ Safety Note**: Network validators are disabled by default (`allow_network: false`) to ensure CI safety. Enable only in trusted environments for live credential validation.

### Validation Results

Validators return one of three states:
- `valid`: Finding successfully validated
- `invalid`: Finding failed validation 
- `indeterminate`: Validation skipped (network disabled, rate limited, or error)

Example output:
```json
{
  "findings": [...],
  "validators": {
    "enabled": true,
    "results": {
      "0": [
        {
          "state": "valid",
          "evidence": "Valid Slack webhook format with enhanced checks: ****5678",
          "reason": "Passed Slack webhook URL pattern and component validation",
          "validator_name": "slack_webhook_local"
        },
        {
          "state": "indeterminate",
          "evidence": "GCP service account key format valid: ****.com",
          "reason": "Format validation passed, but live validation requires full OAuth2 implementation", 
          "validator_name": "gcp_sa_key_live"
        },
        {
          "state": "indeterminate",
          "evidence": null,
          "reason": "Network disabled - validator skipped",
          "validator_name": "azure_sas_live"
        }
      ]
    }
  }
}
```

#### Validator-Specific Examples

**Slack Webhook Validation**:
```bash
# Local validation (always runs)
Finding: https://hooks.slack.com/services/T12345678/B12345678/abcd1234...
Result: "valid" with enhanced component validation

# Both slack_webhook_format and slack_webhook_local will validate this
```

**GCP Service Account Key**:
```bash  
# With network disabled (default)
Finding: {"type": "service_account", "client_email": "...@project.iam.gserviceaccount.com", ...}
Result: "indeterminate" - format validated, live check skipped

# With allow_network: true
Result: "indeterminate" - format validated, but full OAuth2 flow not implemented
```

**Azure SAS Token**:
```bash
# With network disabled (default)  
Finding: https://storage.blob.core.windows.net/container?sv=2020-08-04&se=...&sig=...
Result: "indeterminate" - format validated, HEAD request skipped

# With allow_network: true
Result: "indeterminate" - format validated, HEAD request would be attempted
```

### Security Guarantees

- Network access is **disabled by default** - safe for CI/CD pipelines
- All secrets in validator evidence are **automatically redacted**
- Rate limiting prevents validator abuse and resource exhaustion
- Validation errors gracefully degrade to `indeterminate` state

## 🏗️ CI Integration

### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      
      # Run SS360 scan with policy enforcement
      - name: SS360 Security Scan
        run: |
          ss360 scan . --policy policy.example.yml --format json --json-out findings.json --sarif-out findings.sarif
      
      # Upload SARIF to GitHub Security tab
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
          category: ss360-secrets
      
      # Upload detailed results as artifact
      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: ss360-results
          path: |
            findings.json
            findings.sarif
```

### Policy Gates

The CLI exits with non-zero status when policy violations are found:

```bash
ss360 scan . --policy policy.yml
echo $?  # 0 = passed, 1 = policy violations found
```

This enables CI pipelines to fail builds when security issues are detected.

## 🧪 Testing

Run the test suite:

```bash
# Run custom test suite
python run_tests.py

# Demo end-to-end functionality
./demo_e2e.sh
```

## 📊 Example Outputs

### Text Output
```
🔍 SS360 Scan Results
==================================================
Total findings: 3

Findings by type:
  github_pat: 1
  aws_keypair: 2

High-risk findings:
  Count: 2

🔬 Validation Summary
  Total validations: 6
  Confirmed valid: 2

📋 Policy Enforcement
  Status: ❌ FAILED
  Violations: 2
    - Found 3 findings, but budget allows max 0
    - Finding has risk score 84, exceeds limit 40
```

### Autofix Plan Output
```
Autofix Plan:
========================================

1. Replace GitHub PAT literal with secret reference in src/config.py:5
   Action: remove_literal
   Provider: github
   Reversible: Yes
   Safety: Token will be revoked after replacement

2. Revoke GitHub PAT ****7890 via API
   Action: revoke_token
   Provider: github
   Reversible: No
   Safety: Token revocation cannot be undone
```

## 🚨 Safety Features

- **Network Kill-Switch**: Validators disabled by default for CI safety
- **Evidence Redaction**: All secrets shown as `****last4` in outputs
- **Dry-Run Mode**: All destructive operations support dry-run
- **Explicit Confirmation**: `--i-know-what-im-doing` flag required for apply
- **Reversibility Tracking**: Clear indication of which operations can be undone
- **Rate Limiting**: Token bucket prevents API abuse

## 🔧 Architecture

### Core Components

- **`src/ss360/risk/`**: Risk scoring and assessment
- **`src/ss360/validate/`**: Live validation system
- **`src/ss360/autofix/`**: Automated remediation
- **`src/ss360/policy/`**: Policy enforcement engine
- **`detectors/`**: Secret detection patterns
- **`src/ss360/cli.py`**: Command-line interface

### Extensibility

- **Custom Detectors**: Add new patterns in `detectors/`
- **Custom Validators**: Implement the `Validator` protocol
- **Custom Providers**: Add new autofix providers in `autofix/providers/`
- **Custom Policies**: Extend policy configuration schema

## 📈 Roadmap

- **Additional Detectors**: Database URLs, API keys, private keys
- **Cloud Integration**: AWS Secrets Manager, Azure Key Vault
- **Advanced Analytics**: Trend analysis, false positive learning
- **Enterprise Features**: LDAP integration, advanced reporting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `python run_tests.py`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.