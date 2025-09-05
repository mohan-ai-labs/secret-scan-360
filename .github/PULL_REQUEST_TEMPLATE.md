## Secret Remediation Checklist

Please review this checklist before merging any PR that may contain secret changes or security-related code.

### 🔍 Security Scan Results
- [ ] I have reviewed the SS360 scan results (check the Actions tab)
- [ ] Any security findings have been properly addressed
- [ ] SARIF results have been uploaded and reviewed in the Security tab

### 🔒 Secret Management
- [ ] No plaintext secrets are committed in this PR
- [ ] Any secrets are properly referenced via environment variables or secret managers
- [ ] Legacy hardcoded secrets have been rotated if exposed

### 🛠️ Code Changes
- [ ] Code follows the project's security guidelines
- [ ] Tests have been added/updated for security-related changes
- [ ] Documentation has been updated if needed

### 📋 Policy Compliance
- [ ] Changes comply with the security policy (`policy.example.yml`)
- [ ] Any policy waivers are properly documented and time-bound
- [ ] Risk scores are within acceptable limits

### 🚀 Deployment Safety
- [ ] Changes are safe to deploy without breaking existing functionality
- [ ] Any credential rotations are coordinated with the team
- [ ] Rollback plan is in place if needed

### ⚠️ Special Considerations

**For Autofix PRs:**
- [ ] Autofix changes have been manually reviewed
- [ ] Secret references are correctly configured
- [ ] Old secrets have been properly revoked/deactivated

**For Security Tool Changes:**
- [ ] Changes have been tested against known secret patterns
- [ ] False positive rates are acceptable
- [ ] Performance impact is minimal

---

**Note:** PRs that fail security policy gates may be blocked from merging until issues are resolved or proper waivers are in place.