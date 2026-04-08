# Financial Template

For payment, transfer, billing, and financial operations agents.

---

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `transaction_limit` | 5000 | Max transaction amount before denial |
| `currency` | `"EUR"` | Required currency |
| `business_hours_only` | `true` | Block transactions outside business hours (>= 100) |
| `approval_threshold` | 1000 | Transactions above this require human approval |
| `daily_transaction_cap` | 100 | Max transactions per 24 hours |

---

## Violation Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `transaction_exceeds_limit` | `params.amount >= transaction_limit` | high |
| `currency_mismatch` | `params.currency != configured currency` | medium |
| `transaction_outside_business_hours` | Non-business hours + amount >= 100 | medium |
| `daily_transaction_cap_exceeded` | 24h action count > daily_transaction_cap | medium |

---

## Approval Rules

| Rule | Trigger |
|------|---------|
| `requires_human_approval` | `params.amount >= approval_threshold` (default: 1000) |

---

## Configuration Example

Raise limits for a high-volume trading desk:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "policy_template": "financial",
    "policy_config": {
      "transaction_limit": 50000,
      "currency": "USD",
      "approval_threshold": 10000,
      "daily_transaction_cap": 500,
      "business_hours_only": false
    }
  }'
```
