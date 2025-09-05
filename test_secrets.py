# Sample file with secrets for testing
API_TOKEN = "ghp_1234567890123456789012345678901234567890"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# This is in a test file, should have lower risk score
def test_auth():
    token = "ghp_testtoken1234567890123456789012345678"
    return token
