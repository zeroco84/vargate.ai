package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── CRM & Sales Policy Template ─────────────────────────────────────────────
# Suitable for: Salesforce bots, HubSpot automation, lead management agents
#
# Configurable via input.tenant.policy_config:
#   bulk_threshold:     Records above this count require approval (default: 10)
#   allow_delete:       Whether the agent can delete records (default: false)
#   export_approval:    Require approval for data exports (default: true)
#   restricted_fields:  Fields the agent cannot modify (default: ["owner", "revenue"])

_config := object.union({
    "bulk_threshold": 10,
    "allow_delete": false,
    "export_approval": true,
    "restricted_fields": ["owner", "revenue"],
}, object.get(input, ["tenant", "policy_config"], {}))

# Block record deletion if not allowed
violations contains "crm_delete_not_allowed" if {
    not _config.allow_delete
    input.action.method == "delete"
}

# Block modification of restricted fields
violations contains msg if {
    some field in _config.restricted_fields
    input.action.params.fields[field]
    msg := concat("", ["restricted_field_modification_", field])
}

# Block bulk operations above threshold
violations contains "bulk_operation_exceeds_threshold" if {
    input.action.params.record_count > _config.bulk_threshold
}

# Require approval for data exports
requires_human_approval if {
    _config.export_approval
    input.action.method == "export"
}

# Require approval for bulk modifications
requires_human_approval if {
    input.action.params.record_count > _config.bulk_threshold
}
