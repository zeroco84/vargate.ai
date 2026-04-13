# Twitter / X Integration Guide

Vargate's Twitter integration enables governed posting and management of tweets through the proxy. All actions are logged to the audit trail, evaluated against OPA policy, and executed via brokered credentials (the agent never sees the Bearer token).

## Authentication

Twitter API v2 write endpoints (create/delete tweet) require **OAuth 1.0a User Context**. App-Only Bearer tokens do not work for writes.

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

## Governance Summary

| Tool | Method | GTM Approval Required |
|------|--------|-----------------------|
| `twitter` | `create_tweet` | Yes (content review) |
| `twitter` | `delete_tweet` | Yes (destructive) |
| `twitter` | `get_user_tweets` | No (read-only) |

## API Reference

Twitter API v2 endpoints used:

- **Create tweet:** `POST https://api.twitter.com/2/tweets`
- **Delete tweet:** `DELETE https://api.twitter.com/2/tweets/:id`
- **User tweets:** `GET https://api.twitter.com/2/users/:id/tweets` (Basic tier only)

Write endpoints use OAuth 1.0a (HMAC-SHA1 signature). Read endpoints can use either OAuth 1.0a or App-Only Bearer token. See [Twitter API v2 documentation](https://developer.x.com/en/docs/twitter-api) for full details.
