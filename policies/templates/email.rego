package vargate.policy

import future.keywords.if
import future.keywords.contains

# ── Email & Outreach Policy Template ─────────────────────────────────────────
# Suitable for: GTM agents, customer support bots, newsletter automation
#
# Configurable via input.tenant.policy_config:
#   daily_send_limit:       Max emails per 24h (default: 50)
#   require_disclosure:     Mandate AI-generated disclosure (default: true)
#   first_contact_approval: Require human approval for new recipients (default: true)
#   blocked_domains:        Set of recipient domains to block (default: consumer domains)

_config := object.union({
    "daily_send_limit": 50,
    "require_disclosure": true,
    "first_contact_approval": true,
}, object.get(input, ["tenant", "policy_config"], {}))

_default_blocked := {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "aol.com", "protonmail.com", "proton.me"}

_blocked_domains := object.get(_config, "blocked_domains", _default_blocked)

_is_email_action if { input.action.tool == "email" }
_is_email_action if { input.action.tool == "gmail" }
_is_email_action if { input.action.tool == "resend" }

# Block consumer email domains
violations contains "consumer_email_blocked" if {
    _is_email_action
    some domain in _blocked_domains
    endswith(input.action.params.to, domain)
}

# Block if daily send limit exceeded
violations contains "daily_send_limit_exceeded" if {
    _is_email_action
    input.history.last_24h.action_count > _config.daily_send_limit
}

# Block emails missing AI disclosure
violations contains "missing_ai_disclosure" if {
    _is_email_action
    _config.require_disclosure
    not contains(input.action.params.body, "AI-generated")
    not contains(input.action.params.body, "automated")
}

# First-contact emails require human approval
requires_human_approval if {
    _is_email_action
    _config.first_contact_approval
    not input.context.prior_contact_exists
}
