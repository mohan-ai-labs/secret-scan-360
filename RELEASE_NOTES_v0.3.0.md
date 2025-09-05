# Secret Scan 360 v0.3.0 Release Instructions

This document contains the steps to complete the v0.3.0 release of Secret Scan 360.

## ✅ Completed Steps

1. **Enhanced packaging metadata** - Added comprehensive description and classifiers
2. **Created CHANGELOG.md** - Documented v0.3.0 features and improvements  
3. **Package builds successfully** - Both wheel and source distributions validated
4. **CLI functionality verified** - `ss360` command working with all features

## 🚀 Release Process

### Step 1: Prerelease to TestPyPI (v0.3.0-rc1)

The RC1 version has been prepared. To publish:

```bash
# Update version to 0.3.0rc1 (already done)
# Build the package (already done)
make clean && make build

# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Create git tag
git tag v0.3.0-rc1
git push origin v0.3.0-rc1
```

**TestPyPI Installation Test:**
```bash
pip install --index-url https://test.pypi.org/simple/ secret-scan-360==0.3.0rc1
ss360 --help
ss360 version
```

### Step 2: Final Release to PyPI (v0.3.0)

The final version has been prepared. To publish:

```bash
# Version is already set to 0.3.0
# Package is already built

# Upload to PyPI
python -m twine upload dist/*

# Create git tag
git tag v0.3.0
git push origin v0.3.0
```

**PyPI Installation Test:**
```bash
pip install secret-scan-360
ss360 --help
ss360 version
```

### Step 3: Create GitHub Release

Create a new release on GitHub with:

- **Tag version:** `v0.3.0`
- **Release title:** `Secret Scan 360 v0.3.0`
- **Description:** Use content from CHANGELOG.md
- **Assets:** Attach the built wheel and source distribution

## 📦 Package Details

- **Name:** `secret-scan-360`
- **Version:** `0.3.0`
- **CLI Command:** `ss360`
- **Python Support:** 3.10+
- **License:** MIT

## 🎯 Acceptance Criteria

- ✅ `pipx install secret-scan-360` provides `ss360` CLI
- ✅ Enhanced packaging metadata (description, classifiers)
- ✅ CHANGELOG.md documents v0.3.0 features
- ✅ Package builds and validates successfully

## 📋 Manual Testing Checklist

After publication, test:

```bash
# Install via pip
pip install secret-scan-360

# Install via pipx
pipx install secret-scan-360

# Verify CLI works
ss360 --help
ss360 version
ss360 scan --help
ss360 org --help

# Test basic functionality
ss360 scan .
```

## 🔧 Key Features in v0.3.0

- **Validation System:** Live validation of detected secrets
- **Finding Classification:** Automatic categorization (actual/expired/test/unknown)
- **Organization Scanning:** Enterprise-scale multi-repo scanning
- **Aggregator System:** Consolidated reporting and analysis
- **CI Policy Engine:** Configurable policy enforcement

## 📞 Support

For issues with the release process or package functionality:
- Check the [README.md](README.md) for usage instructions
- Review [CHANGELOG.md](CHANGELOG.md) for feature details
- Report issues on the GitHub repository