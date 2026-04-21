# Twitter / X Integration Guide (internal reference)

> **Customer-facing setup docs live at `docs-site/docs/integrations/twitter.md`** (published to developer.vargate.ai). This file is the internal reference covering the protocol details and credential shapes the customer docs don't need.

Vargate's Twitter integration supports both **OAuth 2.0 User Context** (preferred — unlocks tweet, follow, DM, likes, etc.) and **OAuth 1.0a User Context** (legacy — tweets and basic reads only). All actions are logged to the audit trail, evaluated against OPA policy, and executed via brokered credentials — the agent never sees access tokens.

## Authentication layers

### OAuth 2.0 (preferred)

- Enabled via the **Connect with Twitter** button in Vault Management
- Flow: POST `/oauth/twitter/start` (from the UI) → browser redirect to Twitter → callback at `/api/oauth/twitter/callback` → tokens stored in HSM as `twitter/oauth2`
- Access tokens expire in ~2h; execution engine refreshes transparently via `_twitter_get_bearer_access_token`
- Refresh tokens rotate on every use — the engine persists the new token to HSM *before* using the new access token
- Required for: `send_dm`, `follow_user`, `unfollow_user`, `list_dm_conversations`

### OAuth 1.0a (legacy fallback)

Twitter API v2 write endpoints (create/delete tweet) also accept **OAuth 1.0a User Context**. App-Only Bearer tokens do not work for any writes.

Register the credential in Vargate's HSM vault as a **JSON object**:

- **Tool ID:** `twitter`
- **Credential name:** `api_key`

**Credential value (JSON):**
```json
{
  "api_key": "your-consumer-api-key",
  "api_secret": "your-consumer-api-secret",
  "access_token": "your-user-access-token",
  "access_secret": "your-user-access-token-secret"
}
```

To obtain these keys:

1. Create a project at [developer.x.com](https://developer.x.com)
2. Enable **OAuth 1.0a** with Read and Write permissions in User Authentication Settings
3. Generate or regenerate the Consumer Keys (API Key & Secret)
4. Generate or regenerate the Access Token & Secret (with Read and Write scope)
5. Paste the four values as a JSON object into the Vault Management credential field

## Tools

### vargate_twitter_create_tweet

Post a tweet on Twitter/X.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | yes | Tweet text (max 280 characters) |

**Governance:** Requires human approval on GTM tenant (content review).

**Example:**
```json
{
  "tool": "twitter",
  "method": "create_tweet",
  "params": {
    "text": "We just open-sourced our agent governance framework. Check it out."
  }
}
```

**Response:**
```json
{
  "status": "tweet_created",
  "tweet_id": "1234567890123456789",
  "text": "We just open-sourced our agent governance framework. Check it out."
}
```

### vargate_twitter_delete_tweet

Delete a tweet by ID.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tweet_id` | string | yes | ID of the tweet to delete |

**Governance:** Requires human approval on GTM tenant (destructive action).

**Example:**
```json
{
  "tool": "twitter",
  "method": "delete_tweet",
  "params": { "tweet_id": "1234567890123456789" }
}
```

**Response:**
```json
{
  "status": "tweet_deleted",
  "tweet_id": "1234567890123456789",
  "deleted": true
}
```

### vargate_twitter_get_tweets

Get recent tweets for a user. Read-only.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | string | yes | Twitter user ID |
| `max_results` | integer | no | Max tweets to return (default: 10) |

**Governance:** Allowed without human approval (read-only).

**Free tier limitation:** This endpoint requires the Twitter Basic plan ($100/mo). On the free tier it returns a clear error:
```json
{
  "error": "twitter_free_tier_limit",
  "status_code": 403,
  "detail": "Twitter free tier does not support reading tweets. Upgrade to the Basic plan ($100/mo) at developer.x.com to use this endpoint."
}
```

**Example:**
```json
{
  "tool": "twitter",
  "method": "get_user_tweets",
  "params": { "user_id": "123456789", "max_results": 5 }
}
```

**Response (Basic tier):**
```json
{
  "status": "ok",
  "tweets": [
    { "id": "1234567890123456789", "text": "Hello world" }
  ],
  "count": 1
}
```

### vargate_twitter_follow_user

Follow a Twitter user. **Requires OAuth 2.0** with `follows.write` scope.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target_user_id` | string | yes | Numeric Twitter user id (not handle) |

**Governance:** Requires human approval on GTM tenant (reputational).

### vargate_twitter_unfollow_user

Unfollow a user. **Requires OAuth 2.0** with `follows.write` scope.

Same params as `follow_user`. Requires approval on GTM tenant.

### vargate_twitter_send_dm

Send a direct message. **Requires OAuth 2.0** with `dm.write` scope.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `participant_id` | string | yes | Recipient's numeric Twitter user id |
| `text` | string | yes | Message body (max 10,000 chars) |

**Governance:** Requires human approval on GTM tenant (high spam risk).

Recipient must either follow the sender or have DMs open to non-followers; Twitter returns 403 otherwise.

### vargate_twitter_list_dm_conversations

Read recent DM events. Read-only; requires OAuth 2.0 with `dm.read` scope.

## Governance Summary

| Tool | Method | Auth required | GTM Approval Required |
|------|--------|---------------|-----------------------|
| `twitter` | `create_tweet` | OAuth 1.0a or 2.0 | Yes (content review) |
| `twitter` | `delete_tweet` | OAuth 1.0a or 2.0 | Yes (destructive) |
| `twitter` | `get_user_tweets` | Any | No (read-only) |
| `twitter` | `follow_user` | OAuth 2.0 only | Yes |
| `twitter` | `unfollow_user` | OAuth 2.0 only | Yes |
| `twitter` | `send_dm` | OAuth 2.0 only | Yes |
| `twitter` | `list_dm_conversations` | OAuth 2.0 only | No (read-only) |

## API Reference

Twitter API v2 endpoints used:

- **Create tweet:** `POST https://api.twitter.com/2/tweets`
- **Delete tweet:** `DELETE https://api.twitter.com/2/tweets/:id`
- **User tweets:** `GET https://api.twitter.com/2/users/:id/tweets` (Basic tier only)
- **Follow:** `POST https://api.twitter.com/2/users/:source_id/following`
- **Unfollow:** `DELETE https://api.twitter.com/2/users/:source/following/:target`
- **Send DM:** `POST https://api.twitter.com/2/dm_conversations/with/:id/messages`
- **List DM events:** `GET https://api.twitter.com/2/dm_events`
- **Token:** `POST https://api.twitter.com/2/oauth2/token`

See [Twitter API v2 documentation](https://developer.x.com/en/docs/twitter-api) for full details.

## OAuth 2.0 implementation notes

- PKCE: `secrets.token_urlsafe(64)` verifier, SHA256 challenge, `S256` method
- State: `secrets.token_urlsafe(32)`, stored in Redis with a 10-minute TTL (in-memory fallback for dev)
- Token exchange: `POST /2/oauth2/token` with HTTP Basic auth + form body (`grant_type=authorization_code`)
- Refresh: same endpoint with `grant_type=refresh_token`; **refresh_token rotates on every refresh** — persist new token before using new access_token
- Storage: HSM credential `twitter/oauth2` with JSON `{client_id, client_secret, refresh_token, access_token, access_token_expires_at, scope}`
- When both `twitter/oauth2` and `twitter/api_key` exist in the vault, the execution engine prefers `oauth2`.
