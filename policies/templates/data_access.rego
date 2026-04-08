package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── Data Access Policy Template ──────────────────────────────────────────────
# Suitable for: ETL agents, analytics bots, data pipeline automation
#
# Configurable via input.tenant.policy_config:
#   max_row_limit:       Max rows per query (default: 10000)
#   pii_allowed:         Whether agent can access PII (default: false)
#   allowed_regions:     Data residency regions (default: ["eu-west-1"])
#   require_masking:     Require PII masking in output (default: true)
#   daily_query_limit:   Max queries per 24h (default: 500)

_config := object.union({
    "max_row_limit": 10000,
    "pii_allowed": false,
    "allowed_regions": ["eu-west-1"],
    "require_masking": true,
    "daily_query_limit": 500,
}, object.get(input, ["tenant", "policy_config"], {}))

# Block PII access if not allowed
violations contains "pii_access_denied" if {
    not _config.pii_allowed
    input.data.contains_pii == true
}

# Block unmasked PII output
violations contains "pii_masking_required" if {
    _config.require_masking
    input.data.contains_pii == true
    not input.data.pii_masked
}

# Block queries exceeding row limit
violations contains "query_row_limit_exceeded" if {
    input.action.params.limit > _config.max_row_limit
}

# Block queries to disallowed regions
violations contains "data_residency_violation" if {
    not input.action.params.region in _config.allowed_regions
}

# Block if daily query limit exceeded
violations contains "daily_query_limit_exceeded" if {
    input.history.last_24h.action_count > _config.daily_query_limit
}

# Require approval for full-table exports
requires_human_approval if {
    input.action.method == "export"
    input.action.params.limit > 1000
}
