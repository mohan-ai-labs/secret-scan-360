# Production Configuration - HIGH RISK EXAMPLES
# ⚠️ SYNTHETIC CREDENTIALS ONLY - DO NOT USE IN PRODUCTION ⚠️

import os

class ProductionConfig:
    """Production configuration with embedded secrets (SYNTHETIC EXAMPLES)"""
    
    # GitHub Personal Access Token (classic) - FAKE
    GITHUB_TOKEN = "ghp_1234567890123456789012345678901234567890"
    
    # AWS Access Key - FAKE
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    # Database connection with credentials - FAKE
    DATABASE_URL = "postgresql://admin:supersecret123@prod-db.example.com:5432/myapp"
    
    # API Keys - FAKE
    STRIPE_SECRET_KEY = "sk_live_1234567890123456789012345678901234567890"
    SENDGRID_API_KEY = "SG.1234567890123456789012345678901234567890.abcdefghijklmnopqrstuvwxyz1234567890"
    
    # Slack Webhook - FAKE
    SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

class DatabaseConfig:
    """Database configuration - SYNTHETIC EXAMPLES"""
    
    # MongoDB connection string - FAKE
    MONGO_URI = "mongodb://user:password123@cluster0.mongodb.net/production?retryWrites=true"
    
    # Redis connection - FAKE  
    REDIS_URL = "redis://:mypassword@redis-cluster.example.com:6379/0"
    
    # Elasticsearch credentials - FAKE
    ELASTICSEARCH_URL = "https://elastic:changeme123@search.example.com:9200"

# JWT Secret Key - FAKE
JWT_SECRET = "super-secret-jwt-key-that-should-not-be-in-code-1234567890"

# Encryption keys - FAKE
ENCRYPTION_KEY = "AES256-KEY-32-BYTES-LONG-FAKE-EXAMPLE-1234567890ABCDEF"

# Third-party service tokens - FAKE
TWILIO_AUTH_TOKEN = "abcdef1234567890abcdef1234567890abcdef12"
DATADOG_API_KEY = "1234567890abcdef1234567890abcdef12345678"