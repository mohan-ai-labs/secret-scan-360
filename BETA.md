# Secret Scan 360 - Beta Testing Guide

Welcome to the Secret Scan 360 beta! This guide will get you scanning and securing your repositories in under 5 minutes.

## 🚀 Quick Installation

Install using pipx (recommended for command-line tools):

```bash
# Install pipx if you don't have it
python -m pip install --user pipx
python -m pipx ensurepath

# Install SS360
pipx install git+https://github.com/mohan-ai-labs/secret-scan-360.git
```

Verify installation:
```bash
ss360 --version
```

## ⚡ 5-Minute Quickstart

### 1. Basic Scan
Scan your current directory for secrets:

```bash
ss360 scan .
```

This creates `findings.json` with detected secrets. View the results:
```bash
cat findings.json | jq '.findings[] | {path, line, rule_id, risk_score}'
```

### 2. See Finding Categories
SS360 automatically categorizes findings. View by category:

```bash
# See only actual secrets (highest priority)
ss360 scan . --only-category actual

# See test/demo credentials (lower priority)  
ss360 scan . --only-category test

# See expired tokens (informational)
ss360 scan . --only-category expired
```

### 3. Understand Risk Scoring
See how SS360 scores different types of findings:

```bash
# Create a demo project with secrets
mkdir demo-scan && cd demo-scan
echo 'API_KEY = "ghp_1234567890123456789012345678901234567890"' > config.py
echo 'TEST_KEY = "ghp_testtoken1234567890"' > tests/test_config.py

# Scan and see risk scoring differences
ss360 scan .
cat findings.json | jq '.findings[] | {path, risk_score, category}'
```

This shows how SS360 automatically categorizes and scores findings based on context (test vs production files).

### 4. Policy Gates for CI
Test policy enforcement with different configurations:

```bash
# Strict policy - fails CI on any real secrets
ss360 scan . --policy https://raw.githubusercontent.com/mohan-ai-labs/secret-scan-360/main/policy.example.yml
echo "Exit code: $?"  # 0 = passed, 1 = policy violations

# Demo policy - more permissive for testing
ss360 scan . --policy https://raw.githubusercontent.com/mohan-ai-labs/secret-scan-360/main/policy.demo.yml
echo "Exit code: $?"
```

### 5. Create a Test PR
See how SS360 integrates with your CI pipeline:

1. **Fork the [examples repository](https://github.com/mohan-ai-labs/secret-scan-360)**
2. **Add some test secrets** to a file
3. **Open a Pull Request** - watch SS360 policy gates in action
4. **Review the SARIF security tab** in GitHub

## 🛡️ Safety Defaults

SS360 is designed with security-first defaults:

### CI Safety
- **Network validators disabled by default** (`validators.network: false`)
- **No secrets sent over network** during CI scans
- **Rate limited when network enabled** (2.0 QPS global limit)
- **Read-only operations** - never modifies your code without explicit permission

### Redaction Guarantees
- **Secrets masked in logs** - only shows rule type and location
- **SARIF output sanitized** - no secret values in CI artifacts
- **JSON results configurable** - can exclude secret values entirely

### Autofix Safety
- **Planning mode available** - autofix framework supports dry-run planning
- **Explicit confirmation required** - safety flags for actual changes
- **Backup tracking** - all changes are reversible
- **Pull request workflow** - creates PRs instead of direct commits

> **Note**: Autofix CLI integration is coming soon. Currently available through Python API.

## 📋 Example Policy for CI

Create a `.ss360-policy.yml` in your repo root:

```yaml
version: 1

validators:
  allow_network: false  # Safe for CI - skips network validators
  global_qps: 2.0       # Rate limit when network enabled

budgets:
  new_actual_findings: 0     # Fail CI on real secrets  
  new_expired_findings: 999  # Allow expired (lower risk)
  new_test_findings: 999     # Allow test credentials
  new_unknown_findings: 5    # Limit unclassified findings

autofix:
  min_risk_score: 60         # Only autofix high-risk findings
  require_confirmation: true # Require --i-know-what-im-doing
```

## 🧪 Try the Examples

Explore synthetic examples (safe for testing):

```bash
# Clone examples
git clone https://github.com/mohan-ai-labs/secret-scan-360.git
cd secret-scan-360/examples/leaks

# Scan the examples
ss360 scan .

# See different risk levels
ss360 scan . --only-category actual
ss360 scan . --only-category test

# Test autofix planning (coming soon - Python API available)
# ss360 scan . --autofix plan

# Test with different policies
ss360 scan . --policy policy.example.yml
```

**⚠️ All examples contain only synthetic/fake credentials for testing purposes.**

## 💬 Feedback & Support

We value your feedback! Please help us improve by reporting:

### 🐛 Issues & Feedback
Use our [structured feedback form](https://github.com/mohan-ai-labs/secret-scan-360/issues/new?template=feedback.yml) to report:
- Performance issues
- False positives/negatives  
- Missing detector types
- Developer experience rough edges
- Overall satisfaction rating

### 💬 General Discussion
- [GitHub Discussions](https://github.com/mohan-ai-labs/secret-scan-360/discussions) for questions
- [Documentation](https://github.com/mohan-ai-labs/secret-scan-360/blob/main/README.md) for detailed guides

### 🚨 Security Issues
For security vulnerabilities, please email security@mohan-ai-labs.com instead of filing public issues.

## 🎯 Beta Focus Areas

We're particularly interested in feedback on:

1. **Installation experience** - Was pipx setup smooth?
2. **First-run performance** - How long did your first scan take?
3. **False positive rate** - Are we flagging things that aren't secrets?
4. **Missing detectors** - What secret types should we add?
5. **CI integration** - Does the policy system work for your workflow?
6. **Autofix safety** - Do the safety guards feel appropriate?

## 📈 What's Next

After beta, we're planning:
- **Custom detector plugins**
- **Enterprise SAML/SSO integration** 
- **Slack/Teams notifications**
- **Advanced validation rules**
- **Multi-language SDK support**

Thank you for helping us build a better secret scanner! 🙏

---

**Happy scanning! 🔐**