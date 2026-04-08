# Policy Templates

Vargate includes five pre-built policy templates for common use cases. Each template is a parameterized OPA/Rego policy with configurable defaults that you can override via `policy_config`.

---

## Available Templates

| Template | Use Case | Key Rules |
|----------|----------|-----------|
| [General](general.md) | Default for any agent | Action limits, anomaly detection, destructive action approval |
| [Financial](financial.md) | Payment, transfer, billing agents | Transaction limits, currency enforcement, approval thresholds |
| [Email](email.md) | Outreach, marketing, comms agents | Send limits, consumer domain blocking, AI disclosure |
| [CRM](crm.md) | Sales, CRM, pipeline agents | Bulk operation limits, field restrictions, export approval |
| [Data Access](data-access.md) | ETL, analytics, data pipeline agents | Row limits, PII controls, data residency |

---

## Applying a Template

### List Templates

```bash
curl https://vargate.ai/api/policy/templates \
  -H "X-API-Key: YOUR_KEY"
```

### Apply a Template

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"policy_template": "financial"}'
```

### Override Defaults

Each template has configurable parameters. Override them with `policy_config`:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "policy_template": "financial",
    "policy_config": {
      "transaction_limit": 10000,
      "approval_threshold": 5000
    }
  }'
```

---

## How Config Overrides Work

Templates use the OPA `object.union` pattern: your `policy_config` values are merged with the template defaults. Any key you provide overrides the default. Keys you don't provide keep the default value.

```
Final Config = Default Config + Your Overrides
```

For example, the financial template defaults to `transaction_limit: 5000`. If you set `policy_config: {"transaction_limit": 10000}`, only that value changes — all other defaults remain.
