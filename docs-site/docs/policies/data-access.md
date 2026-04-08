# Data Access Template

For ETL agents, analytics bots, data pipeline automation, and query agents.

---

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_row_limit` | 10000 | Max rows per query |
| `pii_allowed` | `false` | Whether agents can access PII data |
| `allowed_regions` | `["eu-west-1"]` | Permitted data residency regions |
| `require_masking` | `true` | Require PII masking in output |
| `daily_query_limit` | 500 | Max queries per 24 hours |

---

## Violation Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `pii_access_denied` | PII access when `pii_allowed` is false | high |
| `pii_masking_required` | PII in output without masking when `require_masking` is true | high |
| `query_row_limit_exceeded` | `params.limit > max_row_limit` | medium |
| `data_residency_violation` | Query region not in `allowed_regions` | high |
| `daily_query_limit_exceeded` | 24h query count > `daily_query_limit` | medium |

---

## Approval Rules

| Rule | Trigger |
|------|---------|
| `requires_human_approval` | Full-table export with `params.limit > 1000` |

---

## Configuration Example

Allow PII access for an authorized analytics team with US regions:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "policy_template": "data_access",
    "policy_config": {
      "pii_allowed": true,
      "require_masking": false,
      "max_row_limit": 100000,
      "allowed_regions": ["us-east-1", "us-west-2", "eu-west-1"],
      "daily_query_limit": 2000
    }
  }'
```

!!! warning "Data residency"
    The `allowed_regions` setting enforces data residency at the query level. Queries to regions not in the list are blocked. This is critical for GDPR compliance.
