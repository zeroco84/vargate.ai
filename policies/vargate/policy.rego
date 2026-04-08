package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── Structured decision object returned to the gateway ──────────────────────

decision := {
    "allow":           allow,
    "violations":      violations,
    "severity":        severity,
    "requires_human":  requires_human_approval,
    "alert_tier":      alert_tier,
    "evaluation_mode": evaluation_mode,
    "risk_indicators": risk_indicators,
}

default allow := false
allow if { count(violations) == 0 }

default requires_human_approval := false

# ── Evaluation mode (two-pass support) ───────────────────────────────────────

default evaluation_mode := "fast"
evaluation_mode := "needs_enrichment" if { count(risk_indicators) > 0 }

risk_indicators contains "elevated_action_type" if {
    high_risk_tools := {"stripe", "wire_transfer", "payroll"}
    input.action.tool in high_risk_tools
}

risk_indicators contains "large_params" if {
    input.action.params.amount >= 1000
}

risk_indicators contains "off_hours" if {
    input.context.is_business_hours == false
}

# ── Violation rules (all tenants) ────────────────────────────────────────────

# Block tool calls with no credential registered in vault
violations contains msg if {
    input.vault.brokered_execution == true
    not input.action.tool in {t | t := input.vault.credentials_registered[_]}
    msg := "no_credential_registered_for_tool"
}

# ── Violation rules (non-GTM tenants only) ──────────────────────────────────

# Block high-value transactions without approval (EUR)
violations contains msg if {
    not _is_gtm_tenant
    input.action.params.amount >= 5000
    not input.context.approval.granted
    msg := "high_value_transaction_unapproved_eur"
}

# Block unmasked PII leaving EU
violations contains msg if {
    not _is_gtm_tenant
    input.agent.jurisdiction == "EU"
    input.data.contains_pii == true
    input.data.pii_types[_] == "email"
    input.data.residency_required == "EU"
    input.action.params.destination_region != "eu-west-1"
    msg := "gdpr_pii_residency_violation"
}

# Block anomalous behaviour
violations contains msg if {
    not _is_gtm_tenant
    input.history.anomaly_score > 0.7
    msg := "anomaly_score_threshold_exceeded"
}

# Block out-of-hours high-risk actions (EUR)
violations contains msg if {
    not _is_gtm_tenant
    input.context.is_business_hours == false
    input.action.params.amount >= 1000
    msg := "high_value_out_of_hours_eur"
}

# Temporary block: 3+ violations in 24 hours triggers 1-hour cooldown
violations contains msg if {
    not _is_gtm_tenant
    input.history.last_24h.policy_violations >= 3
    input.history.cooldown_active == true
    msg := "violation_cooldown_active"
}

# ── Severity derivation (else chain to avoid recursion) ──────────────────────

is_critical if { "gdpr_pii_residency_violation" in violations }

is_high if {
    "high_value_transaction_unapproved_eur" in violations
    not is_critical
}

is_high if {
    "violation_cooldown_active" in violations
    not is_critical
}

is_high if {
    "no_credential_registered_for_tool" in violations
    not is_critical
}

severity := "critical" if {
    is_critical
} else := "high" if {
    is_high
} else := "medium" if {
    count(violations) > 0
} else := "none"

# ── Alert routing ────────────────────────────────────────────────────────────

alert_tier := "soc_page" if {
    severity == "critical"
} else := "soc_ticket" if {
    severity == "high"
} else := "slack_alert" if {
    severity == "medium"
} else := "none"

# ── Human approval requirement (non-GTM tenants only) ───────────────────────

# Transactions over €5,000 require human approval
requires_human_approval if {
    not _is_gtm_tenant
    input.action.params.amount >= 5000
}
