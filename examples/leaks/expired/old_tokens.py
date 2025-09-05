# JWT tokens with past expiry dates - EXPIRED CATEGORY
# ⚠️ SYNTHETIC EXPIRED TOKENS FOR TESTING ONLY ⚠️

# Expired JWT token (exp: 1640995200 = Jan 1, 2022)
EXPIRED_JWT_1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2NDA5OTUyMDB9.invalid-signature-for-testing-only"

# Another expired JWT (exp: 1609459200 = Jan 1, 2021)  
EXPIRED_JWT_2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCIsImV4cCI6MTYwOTQ1OTIwMH0.fake-signature-expired-token"

class ExpiredTokenConfig:
    """Configuration with expired tokens - should be low priority"""
    
    # JWT that expired in 2022
    OLD_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNjQwOTk1MjAwfQ.expired"
    
    # Fake Azure SAS token that expired
    EXPIRED_SAS = "https://storage.azure.com/container?sv=2020-08-04&se=2022-01-01T00%3A00%3A00Z&sr=c&sp=rl&sig=fakeexpiredsignature"

# Old API tokens that would be expired
LEGACY_TOKENS = [
    "old-api-token-from-2021-fake-example",
    "deprecated-key-expired-2022-01-01",
    "legacy-token-no-longer-valid-fake"
]

# Expired GitHub token format (fake)
OLD_GITHUB_TOKEN = "ghp_expiredtoken123456789012345678901234567890"

# Historical database credentials (fake/expired)
OLD_DB_CONFIG = {
    "host": "old-database.example.com",
    "user": "legacy_user", 
    "password": "old_password_from_2021_fake",
    "database": "deprecated_db"
}