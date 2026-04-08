package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── Financial Services Policy Template ───────────────────────────────────────
# Suitable for: payment agents, treasury bots, accounting automation
#
# Configurable via input.tenant.policy_config:
#   transaction_limit:     Maximum auto-approved amount (default: 5000)
#   currency:              Enforced currency (default: "EUR")
#   business_hours_only:   Require business hours for transactions (default: true)
#   approval_threshold:    Amount requiring human approval (default: 1000)
#   daily_transaction_cap: Max transactions per 24h (default: 100)

_config := object.union({
    "transaction_limit": 5000,
    "currency": "EUR",
    "business_hours_only": true,
    "approval_threshold": 1000,
    "daily_transaction_cap": 100,
}, object.get(input, ["tenant", "policy_config"], {}))

# Block transactions above hard limit
violations contains "transaction_exceeds_limit" if {
    input.action.params.amount >= _config.transaction_limit
}

# Block transactions in wrong currency
violations contains "currency_mismatch" if {
    input.action.params.currency != _config.currency
    input.action.params.currency  # only fire if currency is present
}

# Block out-of-hours transactions
violations contains "transaction_outside_business_hours" if {
    _config.business_hours_only
    input.context.is_business_hours == false
    input.action.params.amount >= 100  # trivial amounts OK
}

# Block if daily cap exceeded
violations contains "daily_transaction_cap_exceeded" if {
    input.history.last_24h.action_count > _config.daily_transaction_cap
}

# Require human approval above threshold
requires_human_approval if {
    input.action.params.amount >= _config.approval_threshold
}
