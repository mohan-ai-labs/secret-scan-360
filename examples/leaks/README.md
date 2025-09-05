# ⚠️ SYNTHETIC EXAMPLES ONLY ⚠️

**WARNING: This directory contains ONLY synthetic/fake credentials for testing purposes.**

These examples are designed to help you:
- Test SS360 detection capabilities
- Understand different risk levels and categories  
- Practice with policy configurations
- Demo autofix planning features

## 🚫 Do NOT Use These Examples For:
- Real authentication in any system
- Production configurations
- Any actual secret storage

## ✅ Safe for Testing:
- Running `ss360 scan` on this directory
- Experimenting with policy configurations
- Testing CI integration workflows
- Demo presentations and training

## 📋 What's Included

### High-Risk Examples (`high-risk/`)
- GitHub Personal Access Tokens
- AWS Access Keys
- Database connection strings
- API keys in production-like configs

### Test Examples (`test-fixtures/`)  
- Credentials in test directories
- Example values in documentation
- Placeholder tokens in templates

### Expired Examples (`expired/`)
- JWT tokens with past expiry dates
- Azure SAS tokens that are expired
- Time-limited credentials that are invalid

## 🧪 Try These Commands

```bash
# Scan all examples
ss360 scan examples/leaks

# See only high-risk findings
ss360 scan examples/leaks --only-category actual

# See test/demo findings
ss360 scan examples/leaks --only-category test

# See expired tokens
ss360 scan examples/leaks --only-category expired

# Test autofix planning (safe - no changes)
ss360 scan examples/leaks --autofix plan

# Test with strict policy
ss360 scan examples/leaks --policy policy.example.yml

# Generate SARIF for CI testing
ss360 scan examples/leaks --sarif-out test-findings.sarif
```

## 🔄 Refreshing Examples

This directory is periodically updated with new examples to test detection of:
- Emerging secret patterns
- New service providers
- Different encoding schemes
- Edge cases and false positive scenarios

Last updated: December 2024

---

**Remember: These are SYNTHETIC examples only. Never use these credentials for real authentication!**