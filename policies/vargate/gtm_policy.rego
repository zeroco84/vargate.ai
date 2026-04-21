package vargate.policy

# ── GTM Agent Rules (Sprint 4) ──────────────────────────────────────────────
#
# These rules apply when input.tenant.id matches the GTM agent tenant.
# They require human approval for ALL outbound email actions and flag
# any self-governance test violations.

import future.keywords.if
import future.keywords.contains

# All email_send actions on the GTM tenant require human approval
# @tools gmail/send_email,resend/send,email/send
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
# @tools substack/create_post,substack/create_note
requires_human_approval if {
    _is_gtm_tenant
    _is_substack_action
    startswith(input.action.method, "create_")
}

# Deleting Substack content requires human approval — destructive action
# @tools substack/delete_note
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
# @tools twitter/create_tweet
requires_human_approval if {
    _is_gtm_tenant
    _is_twitter_publish
}

# Deleting tweets requires human approval — destructive action
# @tools twitter/delete_tweet
requires_human_approval if {
    _is_gtm_tenant
    input.action.tool == "twitter"
    input.action.method == "delete_tweet"
}

# Following users requires human approval — reputational + anti-bot signal
# @tools twitter/follow_user
requires_human_approval if {
    _is_gtm_tenant
    input.action.tool == "twitter"
    input.action.method == "follow_user"
}

# Unfollowing requires human approval — also reputational
# @tools twitter/unfollow_user
requires_human_approval if {
    _is_gtm_tenant
    input.action.tool == "twitter"
    input.action.method == "unfollow_user"
}

# DMs require human approval — high spam/reputation risk
# @tools twitter/send_dm
requires_human_approval if {
    _is_gtm_tenant
    input.action.tool == "twitter"
    input.action.method == "send_dm"
}

# Listing DM conversations is read-only — no approval needed
# (absence of requires_human_approval means auto-allow)

# Reading tweets is allowed without approval (read-only)
# No rule needed — absence of requires_human_approval means auto-allow

_is_twitter_publish if {
    input.action.tool == "twitter"
    input.action.method == "create_tweet"
}

# ── Instagram governance (Sprint 15) ───────────────────────────────────────

# Publishing Instagram posts requires human approval for content review
# @tools instagram/create_post
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

# Brand-safety content filters: profanity and explicit content.
# Applied to EVERY tool call on any string parameter whose field name is
# in _content_fields. Keep the regexes in sync with BLOCKED_PHRASES /
# EXPLICIT_PHRASES in gateway/gtm_constraints.py.
# Word-boundary matching avoids false positives: "country" / "class" /
# "cucumber" / "title" / "cocktail" will NOT match.

_content_fields := {"text", "body", "subject", "caption", "title", "content", "message", "headline", "description", "name"}

_blocked_phrase_regex := `(?i)\b(fuck|fucking|fucked|fucker|fuckers|fuckin|shit|shitty|shitting|bullshit|bitch|bitches|bitching|bastard|bastards|cunt|cunts|asshole|assholes|dickhead|dickheads)\b`

_explicit_phrase_regex := `(?i)\b(pussy|pussies|cock|cocks|suck|sucks|sucked|sucking|sucker|suckers|cum|cums|cumming|tits|titty|titties|ass|asses|orgasm|orgasms|orgasmic|spunk|spunking|jizz|jizzed|jizzing|squirt|squirts|squirting|squirted|blowjob|blowjobs|handjob|handjobs|anal|boobs|boobies|horny|masturbate|masturbating|masturbation|porn|porno|pornography|nudes|boner|boners|nipple|nipples|erection|erections|ejaculate|ejaculates|ejaculating|ejaculation|cunnilingus|fellatio|semen|vagina|vaginas|penis|penises|fetish|fetishes)\b`

violations contains msg if {
    _is_gtm_tenant
    some field in _content_fields
    val := input.action.params[field]
    is_string(val)
    regex.match(_blocked_phrase_regex, val)
    msg := "gtm_blocked_phrase"
}

violations contains msg if {
    _is_gtm_tenant
    some field in _content_fields
    val := input.action.params[field]
    is_string(val)
    regex.match(_explicit_phrase_regex, val)
    msg := "gtm_explicit_content"
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
