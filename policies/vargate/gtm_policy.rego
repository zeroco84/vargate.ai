package vargate.policy

# ── GTM Agent Rules (Sprint 4) ──────────────────────────────────────────────
#
# These rules apply when input.tenant.id matches the GTM agent tenant.
# They require human approval for ALL outbound email actions and flag
# any self-governance test violations.

import future.keywords.if
import future.keywords.contains

# All email_send actions on the GTM tenant require human approval
requires_human_approval if {
    _is_gtm_tenant
    _is_email_action
}

# GTM create actions require human approval
requires_human_approval if {
    _is_gtm_tenant
    input.action.method == "create"
}

# GTM update actions require human approval
requires_human_approval if {
    _is_gtm_tenant
    input.action.method == "update"
}

# GTM delete actions require human approval
requires_human_approval if {
    _is_gtm_tenant
    input.action.method == "delete"
}

# ── Substack governance (Sprint 15) ────────────────────────────────────────

# Creating Substack content (posts and notes) requires human approval for content review
requires_human_approval if {
    _is_gtm_tenant
    _is_substack_action
    startswith(input.action.method, "create_")
}

# Deleting Substack content requires human approval — destructive action
requires_human_approval if {
    _is_gtm_tenant
    _is_substack_action
    startswith(input.action.method, "delete_")
}

# Listing/reading Substack content is allowed without approval (read-only)
# No rule needed — absence of requires_human_approval means auto-allow

_is_substack_action if {
    input.action.tool == "substack"
}

# ── Twitter / X governance (Sprint 15) ────────────────────────────────────

# Publishing tweets requires human approval for content review
requires_human_approval if {
    _is_gtm_tenant
    _is_twitter_publish
}

# Deleting tweets requires human approval — destructive action
requires_human_approval if {
    _is_gtm_tenant
    input.action.tool == "twitter"
    input.action.method == "delete_tweet"
}

# Reading tweets is allowed without approval (read-only)
# No rule needed — absence of requires_human_approval means auto-allow

_is_twitter_publish if {
    input.action.tool == "twitter"
    input.action.method == "create_tweet"
}

# ── Instagram governance (Sprint 15) ───────────────────────────────────────

# Publishing Instagram posts requires human approval for content review
requires_human_approval if {
    _is_gtm_tenant
    input.action.tool == "instagram"
    input.action.method == "create_post"
}

# ── GTM-specific violations ─────────────────────────────────────────────────

# Block GTM agent from sending to consumer email domains
violations contains msg if {
    _is_gtm_tenant
    _is_email_action
    # KEEP IN SYNC with gateway/gtm_constraints.py BLOCKED_DOMAINS
    consumer_domains := {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com", "protonmail.com", "proton.me", "vargate.ai", "vargate.com", "example.com", "test.com", "localhost"}
    some domain in consumer_domains
    endswith(input.action.params.to, domain)
    msg := "gtm_consumer_email_blocked"
}

# Block GTM agent from exceeding daily rate
violations contains msg if {
    _is_gtm_tenant
    _is_email_action
    input.history.last_24h.action_count > 30
    msg := "gtm_daily_rate_exceeded"
}

# ── Helper rules ────────────────────────────────────────────────────────────

_is_gtm_tenant if {
    input.tenant.id == "vargate-gtm-agent"
}

_is_email_action if {
    input.action.tool == "gmail"
    input.action.method == "send_email"
}

_is_email_action if {
    input.action.tool == "email"
    input.action.method == "send"
}

_is_email_action if {
    input.action.tool == "resend"
    input.action.method == "send"
}
