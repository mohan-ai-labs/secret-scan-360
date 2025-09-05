#!/bin/bash
# SS360 End-to-End Demo Script
# This demonstrates the complete secret scanning pipeline

echo "🔒 SS360 End-to-End Secret Scanning Demo"
echo "========================================"

# Create a sample repo with secrets
echo "📁 Setting up demo repository with secrets..."
mkdir -p demo_project/src demo_project/tests

cat > demo_project/src/config.py << 'EOF'
# Production configuration - HIGH RISK
API_TOKEN = "ghp_1234567890123456789012345678901234567890"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://user:pass@localhost/prod"

class Config:
    def __init__(self):
        self.github_token = "ghp_9876543210987654321098765432109876543210"
        self.aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF

cat > demo_project/tests/test_auth.py << 'EOF'
# Test file - LOWER RISK due to path context
def test_github_auth():
    # This is a test token, should be lower risk
    fake_token = "ghp_testtoken1234567890123456789012345678"
    return fake_token

def test_aws_keys():
    test_key = "AKIATEST123456789012"
    return test_key
EOF

echo "✅ Demo project created with various secrets"
echo

echo "🔍 Step 1: Basic scan with policy enforcement"
echo "---------------------------------------------"
python -m ss360.cli scan demo_project --policy policy.example.yml
SCAN_EXIT_CODE=$?
echo "Exit code: $SCAN_EXIT_CODE (non-zero indicates policy violations)"
echo

echo "📊 Step 2: Detailed JSON output with risk scoring"
echo "-------------------------------------------------"
python -m ss360.cli scan demo_project --policy policy.example.yml --format json | jq '.findings[] | {id, path, line, risk_score, risk_level: .risk_summary.level}'
echo

echo "🛠️ Step 3: Generate autofix plan"
echo "-------------------------------"
python -m ss360.cli scan demo_project --policy policy.demo.yml --autofix plan
echo

echo "📋 Step 4: SARIF output for CI integration"
echo "------------------------------------------"
python -m ss360.cli scan demo_project --policy policy.example.yml --format sarif --sarif-out demo_sarif.json
echo "SARIF file created: demo_sarif.json"
echo "Rules found:" $(jq '.runs[0].tool.driver.rules | length' demo_sarif.json)
echo "Results found:" $(jq '.runs[0].results | length' demo_sarif.json)
echo

echo "🧪 Step 5: Run test suite"
echo "------------------------"
python ./run_tests.py
echo

echo "🎯 Demo Summary"
echo "==============="
echo "✅ Detectors: GitHub PAT, AWS Access Keys"
echo "✅ Risk Scoring: Context-aware scoring (0-100)"
echo "✅ Validation: Network-safe live validators"
echo "✅ Policy Enforcement: Budgets, thresholds, waivers"
echo "✅ Autofix Planning: Safe replacement with secret refs"
echo "✅ Output Formats: Text, JSON, SARIF"
echo "✅ CI Integration: Policy gates, SARIF upload"
echo

echo "📖 Try these commands:"
echo "----------------------"
echo "# Scan with different policies:"
echo "ss360 scan . --policy policy.example.yml"
echo "ss360 scan . --policy policy.demo.yml --autofix plan"
echo ""
echo "# Different output formats:"
echo "ss360 scan . --format json"
echo "ss360 scan . --format sarif"
echo ""
echo "# Autofix (with safety flag):"
echo "ss360 scan . --autofix apply --i-know-what-im-doing"
echo ""

# Cleanup
echo "🧹 Cleaning up demo files..."
rm -rf demo_project demo_sarif.json

echo "🎉 Demo completed successfully!"
echo "Ready for production use!"