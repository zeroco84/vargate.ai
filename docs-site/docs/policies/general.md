# General Purpose Template

The default template for any agent type. Provides sensible baselines for rate limiting, anomaly detection, and destructive action gating.

---

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `daily_action_limit` | 200 | Max actions per 24 hours |
| `anomaly_threshold` | 0.7 | Anomaly score threshold for blocking |
| `cooldown_violations` | 3 | Number of violations in 24h before cooldown |
| `approve_destructive` | `true` | Destructive actions require human approval |

---

## Violation Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `anomaly_score_threshold_exceeded` | Agent's anomaly score > `anomaly_threshold` | high |
| `daily_action_limit_exceeded` | 24h action count > `daily_action_limit` | medium |
| `violation_cooldown_active` | Agent has >= `cooldown_violations` violations in 24h | high |

---

## Approval Rules

| Rule | Trigger |
|------|---------|
| `requires_human_approval` | Destructive methods (`delete`, `destroy`, `purge`, `drop`) when `approve_destructive` is true |

---

## Configuration Example

Higher limits for a trusted production agent:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "policy_template": "general",
    "policy_config": {
      "daily_action_limit": 1000,
      "anomaly_threshold": 0.85,
      "cooldown_violations": 5,
      "approve_destructive": true
    }
  }'
```

!!! note "Good starting point"
    The general template is applied by default to new tenants. It provides a reasonable baseline that works for most agent types. Switch to a specialized template when you need domain-specific rules.
