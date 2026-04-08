package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── General Purpose Policy Template ──────────────────────────────────────────
# Suitable for: any agent type. Sensible defaults with configurable limits.
#
# Configurable via input.tenant.policy_config:
#   daily_action_limit:     Max actions per 24h (default: 200)
#   anomaly_threshold:      Anomaly score triggering block (default: 0.7)
#   cooldown_violations:    Violation count triggering cooldown (default: 3)
#   approve_destructive:    Require approval for delete/destroy (default: true)

_config := object.union({
    "daily_action_limit": 200,
    "anomaly_threshold": 0.7,
    "cooldown_violations": 3,
    "approve_destructive": true,
}, object.get(input, ["tenant", "policy_config"], {}))

# Block anomalous behaviour
violations contains "anomaly_score_threshold_exceeded" if {
    input.history.anomaly_score > _config.anomaly_threshold
}

# Block if daily action limit exceeded
violations contains "daily_action_limit_exceeded" if {
    input.history.last_24h.action_count > _config.daily_action_limit
}

# Cooldown after repeated violations
violations contains "violation_cooldown_active" if {
    input.history.last_24h.policy_violations >= _config.cooldown_violations
    input.history.cooldown_active == true
}

# Require approval for destructive actions
requires_human_approval if {
    _config.approve_destructive
    input.action.method in {"delete", "destroy", "purge", "drop"}
}
