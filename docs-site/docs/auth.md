# Authentication

Vargate supports three authentication methods. All API requests (except public endpoints) require one of these.

---

## API Key

The primary method for programmatic access. Pass your API key in the `X-API-Key` header:

```bash
curl https://vargate.ai/api/audit/log \
  -H "X-API-Key: vg-abc123..."
```

### Obtaining Your Key

Your API key is generated when you sign up. You can view it in the dashboard under **Settings**, or retrieve it from the signup response.

### Rotating Your Key

Rotate your API key periodically for security:

```bash
curl -X POST https://vargate.ai/api/api-keys/rotate \
  -H "X-API-Key: YOUR_CURRENT_KEY"
```

The response contains your new key. The old key is immediately invalidated.

!!! warning "Rotation is immediate"
    Update all clients before rotating. The old key stops working instantly.

---

## JWT Session

Used by the web dashboard. Obtain a session token by logging in:

```bash
curl -X POST https://vargate.ai/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com", "password": "your-password"}'
```

Use the token in the `Authorization` header:

```bash
curl https://vargate.ai/api/dashboard/settings \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

Sessions expire after the configured TTL. The dashboard handles token refresh automatically.

---

## GitHub OAuth

Alternative signup and login via GitHub:

1. Navigate to `https://vargate.ai/api/auth/github`
2. Authorize the Vargate application
3. You're redirected back with a session token

---

## Security Best Practices

!!! danger "Never commit API keys"
    Store keys in environment variables or a secrets manager. Never hardcode them in source code.

- **Use environment variables:** `export VARGATE_API_KEY=vg-abc123...`
- **Rotate regularly:** Use `POST /api-keys/rotate` on a schedule
- **Scope access:** Each tenant has its own key with isolated data
- **Monitor access:** Check `GET /credentials/access-log` for credential usage
- **HTTPS only:** All API requests must use HTTPS in production
- **Managed agents:** When using [managed agents](managed-agents/overview.md), your Vargate API key authenticates the MCP server connection. Store the Anthropic API key separately in the [HSM vault](api/credentials.md).

```python
import os
import httpx

client = httpx.Client(
    base_url="https://vargate.ai/api",
    headers={"X-API-Key": os.environ["VARGATE_API_KEY"]},
)
```
