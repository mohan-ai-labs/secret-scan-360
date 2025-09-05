# Test authentication functions - LOWER RISK (test context)
# ⚠️ SYNTHETIC TEST CREDENTIALS ONLY ⚠️

def test_github_authentication():
    """Test GitHub API authentication with fake token"""
    # This is a test token - should be categorized as 'test'
    fake_token = "ghp_testtoken1234567890123456789012345678"
    return authenticate_github(fake_token)

def test_aws_credentials():
    """Test AWS SDK with fake credentials"""
    test_access_key = "AKIATEST123456789012"  
    test_secret_key = "wJalrTestFakeSecretKey123456789012345678"
    return aws_client(test_access_key, test_secret_key)

def test_database_connection():
    """Test database connection with test credentials"""
    test_db_url = "postgresql://testuser:testpass123@localhost:5432/testdb"
    return connect_to_database(test_db_url)

# Mock API keys for testing
TEST_API_KEYS = {
    "stripe": "sk_test_fake123456789012345678901234567890",
    "sendgrid": "SG.fake-test-key.1234567890abcdef", 
    "slack": "xoxb-test-fake-slack-token-123456789012"
}

class TestConfig:
    """Test configuration with fake credentials"""
    JWT_SECRET = "test-jwt-secret-not-for-production"
    DATABASE_URL = "sqlite:///test.db"
    API_KEY = "test-api-key-12345"