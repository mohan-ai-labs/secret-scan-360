# Documentation examples - LOWER RISK (example context)
# ⚠️ SYNTHETIC EXAMPLES FOR DOCUMENTATION ONLY ⚠️

## API Authentication

To authenticate with our API, use your API key:

```bash
curl -H "Authorization: Bearer demo-api-key-example-1234567890" \
     https://api.example.com/v1/users
```

## Environment Variables

Set up your environment variables:

```bash
export API_KEY="example-key-not-real-1234567890abcdef"
export DATABASE_URL="postgresql://demo:example123@localhost/demoapp"
export JWT_SECRET="example-jwt-secret-for-docs-only"
```

## GitHub Actions Example

```yaml
- name: Deploy
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # Use secrets, not hardcoded
    # DON'T DO THIS: GITHUB_TOKEN: "ghp_example123456789012345678901234567890"
```

## Common Mistakes to Avoid

❌ **Don't hardcode secrets:**
```python
STRIPE_KEY = "sk_live_example1234567890"  # This is bad!
```

✅ **Use environment variables:**  
```python
STRIPE_KEY = os.environ["STRIPE_KEY"]  # This is good!
```

## Test Credentials

For testing, you can use these fake credentials:
- Username: `demo@example.com`
- Password: `example-password-123`
- API Key: `demo-12345-fake-api-key`