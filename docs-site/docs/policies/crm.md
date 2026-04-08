# CRM & Sales Template

For CRM, sales pipeline, and customer management agents.

---

## Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `bulk_threshold` | 10 | Max records in a bulk operation before escalation |
| `allow_delete` | `false` | Whether agents can delete CRM records |
| `export_approval` | `true` | Exports require human approval |
| `restricted_fields` | `["owner", "revenue"]` | Fields that cannot be modified by agents |

---

## Violation Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| `crm_delete_not_allowed` | Delete operation when `allow_delete` is false | high |
| `restricted_field_modification_{field}` | Agent modifies a field in `restricted_fields` | high |
| `bulk_operation_exceeds_threshold` | Bulk operation with count > `bulk_threshold` | medium |

---

## Approval Rules

| Rule | Trigger |
|------|---------|
| `requires_human_approval` | Export operations when `export_approval` is true |
| `requires_human_approval` | Bulk modifications exceeding `bulk_threshold` |

---

## Configuration Example

Allow deletes but restrict more fields:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{
    "policy_template": "crm",
    "policy_config": {
      "allow_delete": true,
      "bulk_threshold": 5,
      "restricted_fields": ["owner", "revenue", "stage", "close_date"],
      "export_approval": true
    }
  }'
```
