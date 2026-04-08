# Email & Outreach Template

For email, outreach, marketing, and communications agents.

---

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `daily_send_limit` | 50 | Max emails per 24 hours |
| `require_disclosure` | `true` | Require AI disclosure in email body |
| `first_contact_approval` | `true` | First contact with new recipients requires human approval |
| `blocked_domains` | `["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com", "protonmail.com", "proton.me"]` | Blocked consumer email domains |

---

## Violation Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `consumer_email_blocked` | Recipient domain is in blocked_domains list | high |
| `daily_send_limit_exceeded` | 24h action count > daily_send_limit | medium |
| `missing_ai_disclosure` | Email body doesn't contain "AI-generated" or "automated" | medium |

---

## Approval Rules

| Rule | Trigger |
|------|---------|
| `requires_human_approval` | First contact (no `prior_contact_exists` flag) when `first_contact_approval` is true |

---

## Configuration Example

Allow higher volume for a marketing campaign:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "policy_template": "email",
    "policy_config": {
      "daily_send_limit": 200,
      "require_disclosure": true,
      "first_contact_approval": false,
      "blocked_domains": ["gmail.com", "yahoo.com"]
    }
  }'
```

!!! tip "AI disclosure"
    When `require_disclosure` is true, the email body must contain the text "AI-generated" or "automated". This ensures compliance with transparency regulations.
