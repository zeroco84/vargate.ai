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
}

default allow := false
allow if { count(violations) == 0 }

default requires_human_approval := false

# ── Violation rules ──────────────────────────────────────────────────────────

# Block high-value transactions without approval
violations contains msg if {
    input.action.params.amount >= 5000
    not input.context.approval.granted
    msg := "high_value_transaction_unapproved"
}

# Block emails to competitor domains
violations contains msg if {
    input.action.tool == "gmail"
    input.action.method == "send_email"
    competitor_domains := {"rival.com", "competitor.com", "acmecorp.com"}
    some domain in competitor_domains
    endswith(input.action.params.to, domain)
    msg := "competitor_contact_attempt"
}

# Block unmasked PII leaving EU
violations contains msg if {
    input.agent.jurisdiction == "EU"
    input.data.contains_pii == true
    input.data.pii_types[_] == "email"
    input.data.residency_required == "EU"
    input.action.params.destination_region != "eu-west-1"
    msg := "gdpr_pii_residency_violation"
}

# Block anomalous behaviour
violations contains msg if {
    input.history.anomaly_score > 0.7
    msg := "anomaly_score_threshold_exceeded"
}

# Block out-of-hours high-risk actions
violations contains msg if {
    input.context.is_business_hours == false
    input.action.params.amount >= 1000
    msg := "high_value_out_of_hours"
}

# ── Severity derivation (else chain to avoid recursion) ──────────────────────

is_critical if { "competitor_contact_attempt" in violations }
is_critical if { "gdpr_pii_residency_violation" in violations }

is_high if {
    "high_value_transaction_unapproved" in violations
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

# ── Human approval requirement ───────────────────────────────────────────────

requires_human_approval if { input.action.params.amount >= 5000 }
