# Changelog

All notable changes to Secret Scan 360 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2024-12-05

### Added

- **🔬 Validation System**: Live validation of detected secrets with network and offline validators
  - GitHub PAT validation via API calls
  - AWS key validation with configurable network policies
  - JWT token expiry validation
  - Azure SAS token expiry detection

- **🏷️ Finding Classification**: Automatic categorization of findings into actual/expired/test/unknown
  - Offline expiry detection for JWT and Azure SAS tokens
  - Test marker detection in paths, filenames, and content
  - Validator signal integration for live classification
  - Entropy-based heuristics for test pattern detection

- **📊 Organization Scanning**: Enterprise-scale scanning across multiple repositories
  - Bulk repository scanning with `ss360 org scan-repos`
  - CODEOWNERS integration for responsibility mapping
  - Aggregated findings with owner-based grouping
  - Baseline comparison for tracking changes over time

- **🔄 Aggregator System**: Consolidated reporting and analysis
  - JSON and Markdown summary generation
  - Repository-level and owner-level breakdowns
  - Rule-based and category-based statistics
  - Integration with CI/CD pipelines

- **📋 CI Policy Engine**: Configurable policy enforcement for continuous integration
  - YAML-based policy configuration
  - Finding severity thresholds
  - Category-based filtering (actual vs test findings)
  - Automated baseline updates and comparisons

### Enhanced

- **CLI Interface**: Improved `ss360` command with new subcommands
  - `ss360 scan` - Enhanced local scanning with classification
  - `ss360 org` - Organization-level operations
  - `ss360 version` - Version information

- **Detection Engine**: Expanded detector coverage and accuracy
  - Enhanced GitHub PAT detection
  - Improved AWS key detection
  - Better entropy analysis
  - Reduced false positives

### Fixed

- Improved scanning performance for large repositories
- Enhanced SARIF output format compliance
- Better handling of binary files and large files
- Stabilized CI integration workflows

### Technical

- Python 3.10+ requirement
- Enhanced packaging metadata with proper classifiers
- Comprehensive test suite coverage
- Docker containerization support
- GitHub Actions CI/CD integration

## [0.2.0] - Previous Release

### Added
- Initial secret detection framework
- Basic CLI interface
- Core detector implementations
- SARIF export functionality

---

For more details about specific features and usage examples, see the [README.md](README.md).